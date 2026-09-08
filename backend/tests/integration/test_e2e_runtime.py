from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from itda.api.main import create_app
from itda.cli import e2e_runtime
from itda.cli.freeze_labels import LabelFreezeReceipt
from itda.contracts.profile_release_authority import ProfileReleaseBuildAuthorityResolution
from itda.domain.canonical import canonical_json_bytes

OFFLINE_ENVIRONMENT = {
    "ITDA_NO_NETWORK": "1",
    "MISE_OFFLINE": "1",
    "MISE_NOT_FOUND_AUTO_INSTALL": "0",
    "UV_OFFLINE": "1",
}
REPO_ROOT = Path(__file__).resolve().parents[3]
WEB_ROOT = REPO_ROOT / "web"
PHASE3_CAPABILITIES = (
    "evaluator_a",
    "evaluator_b",
    "evaluator_c",
    "adjudicator",
    "model_runner",
    "builder",
    "approver",
)


@dataclass
class RecordingRunner:
    chromium_executable: Path
    headless_shell_executable: Path | None = None
    overrides: dict[tuple[str, ...], subprocess.CompletedProcess[str]] = field(default_factory=dict)
    calls: list[tuple[str, ...]] = field(default_factory=list)

    def __call__(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout: float,
    ) -> subprocess.CompletedProcess[str]:
        vector = tuple(command)
        self.calls.append(vector)
        if vector in self.overrides:
            return self.overrides[vector]

        tool_locations = {
            "python": "/opt/mise/installs/python/3.13.14",
            "uv": "/opt/mise/installs/uv/0.11.28",
            "node": "/opt/mise/installs/node/24.18.0",
            "pnpm": "/opt/mise/installs/pnpm/11.15.1",
        }
        if vector[:2] == ("mise", "where"):
            tool, version = vector[2].split("@", maxsplit=1)
            assert tool_locations[tool].endswith(version)
            return subprocess.CompletedProcess(vector, 0, f"{tool_locations[tool]}\n", "")
        if vector[:2] == ("mise", "which"):
            tool = vector[2]
            return subprocess.CompletedProcess(
                vector, 0, f"{tool_locations[tool]}/bin/{tool}\n", ""
            )
        if vector == ("python", "--version"):
            return subprocess.CompletedProcess(vector, 0, "Python 3.13.14\n", "")
        if vector == ("uv", "--version"):
            return subprocess.CompletedProcess(vector, 0, "uv 0.11.28\n", "")
        if vector == ("node", "--version"):
            return subprocess.CompletedProcess(vector, 0, "v24.18.0\n", "")
        if vector == ("pnpm", "--version"):
            return subprocess.CompletedProcess(vector, 0, "11.15.1\n", "")
        if vector[:3] == ("uv", "pip", "check"):
            return subprocess.CompletedProcess(
                vector,
                0,
                "All installed packages are compatible\n",
                "",
            )
        if vector[:3] == ("docker", "context", "inspect"):
            return subprocess.CompletedProcess(vector, 0, '"unix:///var/run/docker.sock"\n', "")
        if vector[:3] == ("docker", "image", "inspect"):
            payload = {
                "Id": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "RepoDigests": [f"postgres@sha256:{e2e_runtime.POSTGRES_IMAGE_DIGEST}"],
            }
            return subprocess.CompletedProcess(vector, 0, f"{json.dumps(payload)}\n", "")
        if vector[:2] == ("node", "--input-type=commonjs"):
            headless_shell = self.headless_shell_executable or self.chromium_executable
            payload = {
                "testVersion": e2e_runtime.PLAYWRIGHT_VERSION,
                "coreVersion": e2e_runtime.PLAYWRIGHT_VERSION,
                "browsers": [
                    {
                        "name": "chromium",
                        "revision": e2e_runtime.PLAYWRIGHT_CHROMIUM_REVISION,
                        "executablePath": str(self.chromium_executable),
                    },
                    {
                        "name": "chromium-headless-shell",
                        "revision": e2e_runtime.PLAYWRIGHT_CHROMIUM_REVISION,
                        "executablePath": str(headless_shell),
                    },
                ],
            }
            return subprocess.CompletedProcess(vector, 0, f"{json.dumps(payload)}\n", "")
        raise AssertionError(f"unexpected command: {vector}")


def completed(
    command: tuple[str, ...], returncode: int, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def load_typescript_config(module_name: str, expression: str) -> object:
    script = (
        f'const module = await import("./{module_name}");'
        f"process.stdout.write(JSON.stringify({expression}));"
    )
    result = subprocess.run(
        [
            "mise",
            "exec",
            "--",
            "pnpm",
            "--dir",
            str(WEB_ROOT),
            "exec",
            "node",
            "--input-type=module",
            "--eval",
            script,
        ],
        cwd=WEB_ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return json.loads(result.stdout.splitlines()[-1])


def make_dry_run(target: str) -> str:
    environment = {
        **os.environ,
        **OFFLINE_ENVIRONMENT,
        "CI": "true",
        "ITDA_E2E_FRESH": "1",
    }
    result = subprocess.run(
        ["make", "--dry-run", target],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        env=environment,
        text=True,
        timeout=30,
    )
    return result.stdout


def installed_playwright_bundle() -> dict[str, Path]:
    result = subprocess.run(
        [
            "mise",
            "exec",
            "--",
            "node",
            "--input-type=commonjs",
            "--eval",
            e2e_runtime.PLAYWRIGHT_BUNDLE_PROBE,
        ],
        cwd=WEB_ROOT,
        check=True,
        capture_output=True,
        env={**os.environ, **OFFLINE_ENVIRONMENT},
        text=True,
        timeout=e2e_runtime.PREREQUISITE_TIMEOUT_SECONDS,
    )
    payload = json.loads(result.stdout)
    return {entry["name"]: Path(entry["executablePath"]) for entry in payload["browsers"]}


def test_next_rewrite_is_a_fixed_loopback_v1_route() -> None:
    rewrites = load_typescript_config(
        "next.config.ts",
        "await module.default.rewrites?.() ?? null",
    )

    assert rewrites[0] == {
        "source": "/v1/:path*",
        "destination": "http://127.0.0.1:8000/v1/:path*",
    }


def test_phase3_next_rewrites_and_safe_runtime_fixture_are_membership_free() -> None:
    rewrites = load_typescript_config(
        "next.config.ts",
        "await module.default.rewrites?.() ?? null",
    )
    assert rewrites[1:] == [
        {
            "source": "/internal/evaluation/:path*",
            "destination": "http://127.0.0.1:8000/internal/evaluation/:path*",
        },
        {
            "source": "/internal/test-support/phase3/:path*",
            "destination": "http://127.0.0.1:8000/internal/test-support/phase3/:path*",
        },
    ]

    fixture_path = REPO_ROOT / "fixtures" / "synthetic" / "phase3" / "e2e-runtime.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    assert fixture["synthetic_only"] is True
    assert set(fixture) == {
        "schema_version",
        "synthetic_only",
        "assignment",
        "rubric_reference",
        "sources",
        "evidence_items",
        "release",
    }
    forbidden_keys = {
        "partition",
        "membership",
        "order",
        "complement",
        "labels",
        "model_output",
        "token",
        "credential",
        "password",
        "dsn",
        "restricted_path",
    }

    def visit(value: object) -> None:
        if isinstance(value, dict):
            assert forbidden_keys.isdisjoint(value)
            for nested in value.values():
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(fixture)


def test_playwright_keeps_seven_distinct_phase3_capabilities_in_process_memory() -> None:
    result = load_typescript_config(
        "playwright.config.ts",
        "(() => { const names = ['EVALUATOR_A','EVALUATOR_B','EVALUATOR_C',"
        "'ADJUDICATOR','MODEL_RUNNER','BUILDER','APPROVER']; "
        "const values = names.map((name) => process.env[`ITDA_E2E_PHASE3_${name}_CAPABILITY`]); "
        "return { configured: values.every((value) => "
        "typeof value === 'string' && value.length >= 32), "
        "distinct: new Set(values).size }; })()",
    )
    assert result == {"configured": True, "distinct": 7}


def test_playwright_config_starts_fresh_backend_and_frontend_servers() -> None:
    config = load_typescript_config(
        "playwright.config.ts",
        "({ webServer: module.default.webServer, projects: module.default.projects })",
    )
    assert isinstance(config, dict)
    web_servers = config["webServer"]
    assert isinstance(web_servers, list)
    assert len(web_servers) == 2

    backend, frontend = web_servers
    assert backend["command"] == "make e2e-backend"
    assert backend["cwd"] == str(REPO_ROOT)
    assert backend["url"] == "http://127.0.0.1:8000/v1/questionnaires/current"
    assert backend["reuseExistingServer"] is False
    assert backend["timeout"] == int(
        e2e_runtime.BACKEND_PLAYWRIGHT_READINESS_TIMEOUT_SECONDS * 1_000
    )
    assert backend["gracefulShutdown"]["signal"] == "SIGTERM"
    assert backend["gracefulShutdown"]["timeout"] == 60_000

    assert frontend["command"] == " ".join(e2e_runtime.FRONTEND_PROCESS_COMMAND)
    assert frontend["cwd"] == str(WEB_ROOT)
    assert frontend["url"] == "http://127.0.0.1:5173/start"
    assert frontend["reuseExistingServer"] is False
    assert frontend["timeout"] == 300_000
    assert frontend["gracefulShutdown"]["signal"] == "SIGTERM"
    assert frontend["gracefulShutdown"]["timeout"] == int(
        e2e_runtime.FRONTEND_SHUTDOWN_GRACE_SECONDS * 1_000
    )

    chromium = next(project for project in config["projects"] if project["name"] == "chromium")
    assert chromium["use"].get("headless", True) is True
    assert "channel" not in chromium["use"]
    assert "executablePath" not in chromium["use"]


def test_generated_dependency_roots_avoid_cloud_evictable_defaults() -> None:
    pnpm_result = subprocess.run(
        [
            "mise",
            "exec",
            "--",
            "pnpm",
            "--dir",
            str(WEB_ROOT),
            "config",
            "get",
            "virtual-store-dir",
        ],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        env={**os.environ, **OFFLINE_ENVIRONMENT},
        text=True,
        timeout=30,
    )
    uv_result = subprocess.run(
        [
            "mise",
            "exec",
            "--",
            "python",
            "-c",
            "import os; print(os.environ.get('UV_PROJECT_ENVIRONMENT'))",
        ],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        env={**os.environ, **OFFLINE_ENVIRONMENT},
        text=True,
        timeout=30,
    )

    assert pnpm_result.stdout.strip() == ".pnpm.nosync"
    assert uv_result.stdout.strip() == ".venv.nosync"


def test_make_targets_keep_preflight_and_browser_execution_offline() -> None:
    preflight = make_dry_run("phase-01-uat-preflight")
    backend = make_dry_run("e2e-backend")
    lifecycle = make_dry_run("phase-01-uat-lifecycle")
    journey = make_dry_run("phase-01-uat")
    gate = make_dry_run("phase-01-uat-gate")

    for recipe in (preflight, backend, lifecycle, journey, gate):
        assert "CI=true" in recipe
        assert "ITDA_NO_NETWORK=1" in recipe
        assert "ITDA_E2E_FRESH=1" in recipe
        assert "MISE_OFFLINE=1" in recipe
        assert "MISE_NOT_FOUND_AUTO_INSTALL=0" in recipe
        assert "UV_OFFLINE=1" in recipe
        assert " --offline " in f" {recipe} "
        assert " --no-sync " in f" {recipe} "
        assert " --frozen " in f" {recipe} "
        assert " --no-python-downloads " in f" {recipe} "

    assert "itda.cli.e2e_runtime --preflight-only" in preflight
    assert "itda.cli.e2e_runtime --preflight-only" not in backend
    assert "itda.cli.e2e_runtime" in backend
    assert "itda.cli.e2e_runtime --lifecycle-gate" in lifecycle
    assert "start-quiz-profile.spec.ts" not in lifecycle
    assert "start-quiz-profile.spec.ts" in journey
    assert "runtime-lifecycle.spec.ts" not in journey
    assert "phase-01-uat-lifecycle" in gate
    assert "phase-01-uat" in gate


def test_preflight_rejects_missing_offline_boundary_before_any_command(
    tmp_path: Path,
) -> None:
    browser = tmp_path / "chrome"
    browser.touch(mode=0o700)

    for variable in OFFLINE_ENVIRONMENT:
        environment = OFFLINE_ENVIRONMENT.copy()
        del environment[variable]
        runner = RecordingRunner(browser, browser)

        with pytest.raises(e2e_runtime.PreflightError, match=variable):
            e2e_runtime.preflight(environment=environment, runner=runner)

        assert runner.calls == []


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("ITDA_NO_NETWORK", "true"),
        ("MISE_OFFLINE", "false"),
        ("MISE_NOT_FOUND_AUTO_INSTALL", "1"),
        ("UV_OFFLINE", ""),
    ],
)
def test_preflight_requires_exact_offline_values(tmp_path: Path, variable: str, value: str) -> None:
    browser = tmp_path / "chrome"
    browser.touch(mode=0o700)
    runner = RecordingRunner(browser, browser)
    environment = {**OFFLINE_ENVIRONMENT, variable: value}

    with pytest.raises(e2e_runtime.PreflightError, match=variable):
        e2e_runtime.preflight(environment=environment, runner=runner)

    assert runner.calls == []


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("DOCKER_HOST", "tcp://docker.example.test:2376"),
        ("DOCKER_HOST", "ssh://builder.example.test"),
        ("DOCKER_CONTEXT", "remote-builder"),
    ],
)
def test_preflight_rejects_remote_docker_routing_before_any_command(
    tmp_path: Path, variable: str, value: str
) -> None:
    browser = tmp_path / "chrome"
    browser.touch(mode=0o700)
    runner = RecordingRunner(browser, browser)

    with pytest.raises(e2e_runtime.PreflightError, match=variable):
        e2e_runtime.preflight(
            environment={**OFFLINE_ENVIRONMENT, variable: value},
            runner=runner,
        )

    assert runner.calls == []


def test_preflight_rejects_active_remote_docker_context_before_image_inspection(
    tmp_path: Path,
) -> None:
    browser = tmp_path / "chrome"
    browser.touch(mode=0o700)
    runner = RecordingRunner(browser, browser)
    command = (
        "docker",
        "context",
        "inspect",
        "--format",
        "{{json .Endpoints.docker.Host}}",
    )
    runner.overrides[command] = completed(command, 0, '"ssh://builder.example.test"\n')

    with pytest.raises(e2e_runtime.PreflightError, match="local Unix socket"):
        e2e_runtime.preflight(environment=OFFLINE_ENVIRONMENT, runner=runner)

    assert not any(call[:3] == ("docker", "image", "inspect") for call in runner.calls)


def test_preflight_checks_pinned_installed_artifacts_without_side_effect_commands(
    tmp_path: Path,
) -> None:
    browser = tmp_path / "chrome"
    browser.touch(mode=0o700)
    headless_shell = tmp_path / "headless-shell"
    headless_shell.touch(mode=0o700)
    runner = RecordingRunner(browser, headless_shell)

    report = e2e_runtime.preflight(environment=OFFLINE_ENVIRONMENT, runner=runner)

    assert report.chromium_executable == browser
    assert report.chromium_headless_shell_executable == headless_shell
    assert report.chromium_revision == "1228"
    flattened = " ".join(" ".join(command) for command in runner.calls)
    assert "uv pip check --python" in flattened
    assert "docker image inspect" in flattened
    assert "--pull" not in flattened
    for forbidden in (" sync ", " install ", " download ", " compose up", "uvicorn"):
        assert forbidden not in f" {flattened} "


def test_backend_environment_check_uses_configured_uv_project_path(tmp_path: Path) -> None:
    runner = RecordingRunner(tmp_path / "browser", tmp_path / "headless-shell")
    environment = {
        **OFFLINE_ENVIRONMENT,
        "UV_PROJECT_ENVIRONMENT": ".venv.nosync",
    }

    e2e_runtime._verify_backend_environment(environment=environment, runner=runner)

    assert runner.calls == [
        (
            "uv",
            "pip",
            "check",
            "--python",
            str(e2e_runtime.BACKEND_ROOT / ".venv.nosync" / "bin" / "python"),
        )
    ]


def test_preflight_rejects_wrong_tool_before_docker_or_browser(
    tmp_path: Path,
) -> None:
    browser = tmp_path / "chrome"
    browser.touch(mode=0o700)
    runner = RecordingRunner(browser, browser)
    command = ("node", "--version")
    runner.overrides[command] = completed(command, 0, "v24.17.0\n")

    with pytest.raises(e2e_runtime.PreflightError, match="node 24.18.0"):
        e2e_runtime.preflight(environment=OFFLINE_ENVIRONMENT, runner=runner)

    assert not any(call[:2] == ("docker", "image") for call in runner.calls)
    assert not any(call[:2] == ("node", "--input-type=commonjs") for call in runner.calls)


def test_preflight_rejects_missing_pinned_image_before_browser_probe(
    tmp_path: Path,
) -> None:
    browser = tmp_path / "chrome"
    browser.touch(mode=0o700)
    runner = RecordingRunner(browser, browser)
    command = (
        "docker",
        "image",
        "inspect",
        e2e_runtime.POSTGRES_IMAGE,
        "--format",
        "{{json .}}",
    )
    runner.overrides[command] = completed(command, 1, stderr="No such image")

    with pytest.raises(e2e_runtime.PreflightError, match="PostgreSQL"):
        e2e_runtime.preflight(environment=OFFLINE_ENVIRONMENT, runner=runner)

    assert not any(call[:2] == ("node", "--input-type=commonjs") for call in runner.calls)


def test_preflight_rejects_wrong_or_missing_chromium_bundle(tmp_path: Path) -> None:
    browser = tmp_path / "chrome"
    browser.touch(mode=0o700)
    headless_shell = tmp_path / "missing-headless-shell"
    runner = RecordingRunner(browser, headless_shell)

    with pytest.raises(
        e2e_runtime.PreflightError,
        match="chromium-headless-shell revision 1228 executable",
    ):
        e2e_runtime.preflight(environment=OFFLINE_ENVIRONMENT, runner=runner)

    probe = next(call for call in runner.calls if call[:2] == ("node", "--input-type=commonjs"))
    runner = RecordingRunner(browser, browser)
    runner.overrides[probe] = completed(
        probe,
        0,
        json.dumps(
            {
                "testVersion": "1.61.1",
                "coreVersion": "1.61.1",
                "browsers": [
                    {
                        "name": "chromium",
                        "revision": "1227",
                        "executablePath": str(browser),
                    },
                    {
                        "name": "chromium-headless-shell",
                        "revision": "1228",
                        "executablePath": str(browser),
                    },
                ],
            }
        ),
    )
    with pytest.raises(e2e_runtime.PreflightError, match="chromium revision 1228"):
        e2e_runtime.preflight(environment=OFFLINE_ENVIRONMENT, runner=runner)


@dataclass
class RecordingLifecycle:
    fail_at: str | None = None
    cleanup_fails: bool = False
    events: list[str] = field(default_factory=list)
    allocated: bool = False
    stop_requested: object | None = None

    def set_stop_event(self, stop_requested: object) -> None:
        self.stop_requested = stop_requested

    def allocate(self) -> object:
        self.events.append("allocate")
        self.allocated = True
        return object()

    def compose_up(self, _resources: object) -> None:
        self._record("compose_up")

    def migrate(self, _resources: object) -> None:
        self._record("migrate")

    def verify_runtime_role(self, _resources: object) -> None:
        self._record("verify_runtime_role")

    def start_api(self, _resources: object) -> object:
        self._record("start_api")
        return object()

    def wait_ready(self, _resources: object, _api_process: object) -> None:
        self._record("wait_ready")

    def wait_until_stopped(
        self, _resources: object, _api_process: object, _stop_requested: object
    ) -> None:
        self._record("wait_until_stopped")

    def stop_api(self, _api_process: object) -> None:
        self.events.append("stop_api")

    def cleanup_private_output(self, _resources: object) -> None:
        self.events.append("cleanup_private_output")
        if self.cleanup_fails:
            raise RuntimeError("private output cleanup failed")

    def drop_database_and_role(self, _resources: object) -> None:
        self.events.append("drop_database_and_role")

    def compose_down(self, _resources: object) -> None:
        self.events.append("compose_down")

    def _record(self, name: str) -> None:
        self.events.append(name)
        if self.fail_at == name:
            raise RuntimeError(f"{name} failed")


@dataclass
class FakeClock:
    now: float = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def runtime_resources() -> e2e_runtime.RuntimeResources:
    return e2e_runtime.RuntimeResources(
        suffix="test",
        project_name="itda_e2e_test",
        database_name="itda_e2e_test",
        admin_name="itda_admin_test",
        runtime_name="itda_runtime_test",
        port=54327,
        phase3_role_names={
            capability: f"itda_label_{capability}_test" for capability in PHASE3_CAPABILITIES
        },
        phase3_capabilities={
            capability: f"synthetic-capability-{capability}" for capability in PHASE3_CAPABILITIES
        },
        phase3_passwords={
            capability: f"synthetic-password-{capability}" for capability in PHASE3_CAPABILITIES
        },
        phase3_dsns={
            capability: (
                f"postgresql://itda_label_{capability}_test:synthetic@127.0.0.1:54327/itda_e2e_test"
            )
            for capability in PHASE3_CAPABILITIES
        },
        admin_password="admin",
        runtime_password="runtime",
        profile_release_authority_password="authority",
        photo_service_password="photo-service",
        profile_session_service_password="profile-session-service",
        profile_session_current_key="Y3VycmVudC1zZXNzaW9uLWtleS0zMi1ieXRlcyEhISE",
        profile_session_previous_key="cHJldmlvdXMtc2Vzc2lvbi1rZXktMzItYnl0ZXMhIQ",
        compose_environment={},
        admin_dsn="postgresql://admin:admin@127.0.0.1:54327/itda_e2e_test",
        admin_postgres_dsn="postgresql://admin:admin@127.0.0.1:54327/postgres",
        runtime_dsn="postgresql://runtime:runtime@127.0.0.1:54327/itda_e2e_test",
        profile_release_authority_dsn=(
            "postgresql://itda_profile_release_authority_service:authority@"
            "127.0.0.1:54327/itda_e2e_test"
        ),
        label_freeze_directory=Path("/nonexistent/itda-phase3-freeze-test"),
        label_freeze_output=Path("/nonexistent/itda-phase3-freeze-test/label-freeze-receipt.json"),
        label_freeze_directory_identity=(0, 0),
        photo_service_dsn=(
            "postgresql://itda_photo_service:photo-service@127.0.0.1:54327/itda_e2e_test"
        ),
        profile_session_service_dsn=(
            "postgresql://itda_current_profile_session_service:profile-session-service@"
            "127.0.0.1:54327/itda_e2e_test"
        ),
        photo_quarantine_directory=Path("/nonexistent/itda-phase6-quarantine-test"),
        photo_quarantine_directory_identity=(0, 0),
    )


def test_phase3_runtime_allocates_seven_distinct_private_server_bindings() -> None:
    lifecycle = e2e_runtime.DefaultRuntimeLifecycle(
        OFFLINE_ENVIRONMENT | {"ITDA_E2E_RUN_ID": "phase3-authority"}
    )

    resources = lifecycle.allocate()

    assert tuple(resources.phase3_role_names) == PHASE3_CAPABILITIES
    assert tuple(resources.phase3_dsns) == PHASE3_CAPABILITIES
    assert tuple(resources.phase3_capabilities) == PHASE3_CAPABILITIES
    assert len(set(resources.phase3_role_names.values())) == 7
    assert len(set(resources.phase3_dsns.values())) == 7
    assert len(set(resources.phase3_capabilities.values())) == 7
    assert resources.phase3_role_names["builder"] != resources.phase3_role_names["approver"]
    assert resources.phase3_dsns["builder"] != resources.phase3_dsns["approver"]
    assert resources.phase3_capabilities["builder"] != resources.phase3_capabilities["approver"]
    assert resources.profile_session_current_key != resources.profile_session_previous_key
    assert len(resources.profile_session_current_key) == 43
    assert len(resources.profile_session_previous_key) == 43

    diagnostics = repr(resources)
    for secret in resources.secrets:
        assert secret not in diagnostics


def _remove_test_freeze_output(resources: object) -> None:
    output = getattr(resources, "label_freeze_output", None)
    directory = getattr(resources, "label_freeze_directory", None)
    if isinstance(output, Path):
        output.unlink(missing_ok=True)
    if isinstance(directory, Path):
        directory.chmod(0o700)
        directory.rmdir()


def test_label_freeze_output_allocate_is_private_unique_absent_and_caller_independent(
    tmp_path: Path,
) -> None:
    caller_output = tmp_path / "caller-selected.json"
    caller_output.write_bytes(b"caller-owned")
    environment = OFFLINE_ENVIRONMENT | {
        "ITDA_E2E_RUN_ID": "same-public-run",
        "ITDA_PHASE3_LABEL_FREEZE_OUTPUT": str(caller_output),
    }

    with ThreadPoolExecutor(max_workers=2) as executor:
        resources = list(
            executor.map(
                lambda _: e2e_runtime.DefaultRuntimeLifecycle(environment).allocate(),
                range(2),
            )
        )

    try:
        directories = {item.label_freeze_directory for item in resources}
        outputs = {item.label_freeze_output for item in resources}
        assert len(directories) == 2
        assert len(outputs) == 2
        for item in resources:
            assert item.label_freeze_output.parent == item.label_freeze_directory
            assert item.label_freeze_output.name == "label-freeze-receipt.json"
            assert stat.S_IMODE(item.label_freeze_directory.lstat().st_mode) == 0o700
            assert not item.label_freeze_output.exists()
            assert not item.label_freeze_output.is_symlink()
            assert item.label_freeze_output != caller_output
            assert str(item.label_freeze_directory) not in repr(item)
            assert str(item.label_freeze_output) not in repr(item)
        assert caller_output.read_bytes() == b"caller-owned"
    finally:
        for item in resources:
            _remove_test_freeze_output(item)


def test_label_freeze_output_inject_is_backend_only_and_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    caller_output = "/tmp/never-use-caller-freeze-output"
    environment = OFFLINE_ENVIRONMENT | {
        "ITDA_E2E_RUN_ID": "freeze-inject",
        "ITDA_PHASE3_LABEL_FREEZE_OUTPUT": caller_output,
    }
    lifecycle = e2e_runtime.DefaultRuntimeLifecycle(environment)
    resources = lifecycle.allocate()
    captured: dict[str, object] = {}

    def capture_popen(command: Sequence[str], **kwargs: object) -> object:
        captured["command"] = tuple(command)
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(e2e_runtime.subprocess, "Popen", capture_popen)
    try:
        lifecycle.start_api(resources)

        command = captured["command"]
        assert command == (
            sys.executable,
            "-m",
            "uvicorn",
            "itda.api.main:app",
            "--host",
            e2e_runtime.API_HOST,
            "--port",
            str(e2e_runtime.API_PORT),
            "--no-proxy-headers",
        )
        makefile = (e2e_runtime.REPOSITORY_ROOT / "Makefile").read_text()
        assert (
            "uvicorn itda.api.main:app --reload --host 127.0.0.1 --port 8000 --no-proxy-headers"
        ) in makefile
        assert "$(PNPM) dev -H 127.0.0.1 -p 5173" in makefile
        child_environment = captured["env"]
        assert isinstance(child_environment, Mapping)
        assert child_environment["ITDA_PHASE3_LABEL_FREEZE_OUTPUT"] == str(
            resources.label_freeze_output
        )
        assert caller_output not in child_environment.values()
        assert "ITDA_PHASE3_LABEL_FREEZE_OUTPUT" not in resources.compose_environment
        assert "ITDA_PHASE3_LABEL_FREEZE_OUTPUT" not in e2e_runtime._safe_environment(environment)
        diagnostic = " ".join(
            (str(resources.label_freeze_directory), str(resources.label_freeze_output))
        )
        redacted = e2e_runtime.redact_diagnostic(diagnostic, resources.secrets)
        assert str(resources.label_freeze_directory) not in redacted
        assert str(resources.label_freeze_output) not in redacted
        assert redacted.count("<redacted>") >= 1
    finally:
        _remove_test_freeze_output(resources)


def test_label_freeze_output_preexisting_destination_is_rejected_before_inject() -> None:
    lifecycle = e2e_runtime.DefaultRuntimeLifecycle(
        OFFLINE_ENVIRONMENT | {"ITDA_E2E_RUN_ID": "freeze-preexisting"}
    )
    resources = lifecycle.allocate()
    resources.label_freeze_output.write_bytes(b"preexisting")
    try:
        with pytest.raises(RuntimeError, match="freeze output validation failed"):
            lifecycle.start_api(resources)
        assert resources.label_freeze_output.read_bytes() == b"preexisting"
    finally:
        _remove_test_freeze_output(resources)


def test_label_freeze_output_symlink_and_parent_permission_drift_are_rejected(
    tmp_path: Path,
) -> None:
    lifecycle = e2e_runtime.DefaultRuntimeLifecycle(
        OFFLINE_ENVIRONMENT | {"ITDA_E2E_RUN_ID": "freeze-symlink"}
    )
    resources = lifecycle.allocate()
    canary = tmp_path / "external-canary"
    canary.write_bytes(b"external")
    resources.label_freeze_output.symlink_to(canary)
    try:
        with pytest.raises(RuntimeError, match="freeze output validation failed"):
            lifecycle.start_api(resources)
        assert canary.read_bytes() == b"external"

        resources.label_freeze_output.unlink()
        resources.label_freeze_directory.chmod(0o755)
        with pytest.raises(RuntimeError, match="freeze output validation failed"):
            lifecycle.start_api(resources)
        assert canary.read_bytes() == b"external"
    finally:
        _remove_test_freeze_output(resources)


def test_runtime_handoffs_freeze_receipt_to_server_authority_graph() -> None:
    lifecycle = e2e_runtime.DefaultRuntimeLifecycle(
        OFFLINE_ENVIRONMENT | {"ITDA_E2E_RUN_ID": "freeze-authority-handoff"}
    )
    resources = lifecycle.allocate()
    receipt = LabelFreezeReceipt(
        accepted_revision_set_sha256="1" * 64,
        adjudicated_label_export_sha256="2" * 64,
        aggregate_set_sha256="3" * 64,
        rubric_sha256="4" * 64,
        source_root_sha256="5" * 64,
        dev_lineage_sha256="6" * 64,
        code_version_sha256="7" * 64,
        config_version_sha256="8" * 64,
        frozen_at="2026-08-06T00:00:00Z",
    )
    resources.label_freeze_output.write_bytes(canonical_json_bytes(receipt.model_dump(mode="json")))

    try:
        handoff = lifecycle.handoff_release_authority(resources)

        assert handoff.freeze_receipt_sha256 == receipt.receipt_sha256
        assert handoff.candidate_freeze_receipt_sha256 == receipt.receipt_sha256
        assert handoff.authority_directory == resources.release_authority_directory
        assert stat.S_IMODE(handoff.authority_directory.lstat().st_mode) == 0o700
        assert not handoff.authority_directory.is_symlink()
        assert handoff.candidate_manifest_path.parent == handoff.authority_directory
        assert (
            handoff.candidate_manifest_sha256
            == hashlib.sha256(handoff.candidate_manifest_path.read_bytes()).hexdigest()
        )
        assert handoff.server_environment["ITDA_PHASE3_CANDIDATE_MANIFEST"] == str(
            handoff.candidate_manifest_path
        )
        assert (
            handoff.server_environment["ITDA_PHASE3_CANDIDATE_MANIFEST_SHA256"]
            == handoff.candidate_manifest_sha256
        )
        resolution = resources.release_build_authority_resolution
        assert isinstance(resolution, ProfileReleaseBuildAuthorityResolution)
        assert resolution.candidate.builder_principal == "phase3-builder"
        assert resolution.builder_database_principal == resources.phase3_role_names["builder"]
        for name in (
            "LABEL_FREEZE",
            "CANDIDATE",
            "REVIEWED",
            "RIGHTS",
            "SOURCE",
        ):
            path_key = f"ITDA_PHASE3_PROFILE_RELEASE_{name}_MANIFEST"
            digest_key = f"ITDA_PHASE3_PROFILE_RELEASE_{name}_SHA256"
            assert path_key in handoff.server_environment
            assert digest_key in handoff.server_environment
        rendered = json.dumps(handoff.public_receipt, sort_keys=True)
        for secret in resources.secrets:
            assert secret not in rendered
        assert str(handoff.authority_directory) not in rendered
    finally:
        lifecycle.begin_cleanup()
        lifecycle.cleanup_private_output(resources)


@pytest.mark.parametrize("operation", ("validate", "cleanup"))
def test_release_authority_descriptor_swap_is_terminal_and_preserves_resource_state(
    operation: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lifecycle = e2e_runtime.DefaultRuntimeLifecycle(
        OFFLINE_ENVIRONMENT | {"ITDA_E2E_RUN_ID": f"authority-swap-{operation}"}
    )
    resources = lifecycle.allocate()
    receipt = LabelFreezeReceipt(
        accepted_revision_set_sha256="1" * 64,
        adjudicated_label_export_sha256="2" * 64,
        aggregate_set_sha256="3" * 64,
        rubric_sha256="4" * 64,
        source_root_sha256="5" * 64,
        dev_lineage_sha256="6" * 64,
        code_version_sha256="7" * 64,
        config_version_sha256="8" * 64,
        frozen_at="2026-08-06T00:00:00Z",
    )
    resources.label_freeze_output.write_bytes(canonical_json_bytes(receipt.model_dump(mode="json")))
    handoff = lifecycle.handoff_release_authority(resources)
    active = handoff.authority_directory
    substitute = active.with_name("release-authority-substitute")
    displaced = active.with_name("release-authority-original")
    shutil.copytree(active, substitute)
    real_open = os.open
    swapped = False

    def swap_before_authority_open(
        path: os.PathLike[str] | str,
        flags: int,
        *args: object,
        **kwargs: object,
    ) -> int:
        nonlocal swapped
        dir_fd = kwargs.get("dir_fd")
        target_is_authority = os.fspath(path) == os.fspath(active) or (
            os.fspath(path) == e2e_runtime.RELEASE_AUTHORITY_DIRECTORY_NAME and dir_fd is not None
        )
        if not swapped and target_is_authority:
            swapped = True
            os.rename(active, displaced)
            os.rename(substitute, active)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(e2e_runtime.os, "open", swap_before_authority_open)
    try:
        with pytest.raises(RuntimeError, match="private release authority .* failed"):
            if operation == "validate":
                lifecycle._validate_release_authority(resources)
            else:
                e2e_runtime._cleanup_release_authority(resources)
        assert swapped is True
        assert resources.release_authority_directory == active
        assert resources.release_authority_directory_identity is not None
        assert resources.release_authority_environment
        assert displaced.is_dir()
    finally:
        monkeypatch.setattr(e2e_runtime.os, "open", real_open)
        for directory in (active, substitute, displaced):
            if directory.exists():
                shutil.rmtree(directory)
        resources.release_authority_directory = None
        resources.release_authority_directory_identity = None
        resources.release_authority_environment.clear()
        resources.release_reviewed_records = ()
        lifecycle.begin_cleanup()
        lifecycle.cleanup_private_output(resources)


def test_release_authority_swap_after_open_fails_before_api_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lifecycle = e2e_runtime.DefaultRuntimeLifecycle(
        OFFLINE_ENVIRONMENT | {"ITDA_E2E_RUN_ID": "authority-swap-after-open"}
    )
    resources = lifecycle.allocate()
    receipt = LabelFreezeReceipt(
        accepted_revision_set_sha256="1" * 64,
        adjudicated_label_export_sha256="2" * 64,
        aggregate_set_sha256="3" * 64,
        rubric_sha256="4" * 64,
        source_root_sha256="5" * 64,
        dev_lineage_sha256="6" * 64,
        code_version_sha256="7" * 64,
        config_version_sha256="8" * 64,
        frozen_at="2026-08-06T00:00:00Z",
    )
    resources.label_freeze_output.write_bytes(canonical_json_bytes(receipt.model_dump(mode="json")))
    handoff = lifecycle.handoff_release_authority(resources)
    active = handoff.authority_directory
    substitute = active.with_name("release-authority-after-open-substitute")
    displaced = active.with_name("release-authority-after-open-original")
    shutil.copytree(active, substitute)
    real_read = e2e_runtime._read_private_regular_file
    swapped = False

    def swap_after_descriptor_open(
        parent_descriptor: int,
        name: str,
        *,
        max_bytes: int = 2_000_000,
    ) -> bytes:
        nonlocal swapped
        if not swapped:
            swapped = True
            os.rename(active, displaced)
            os.rename(substitute, active)
        return real_read(parent_descriptor, name, max_bytes=max_bytes)

    def reject_api_start(*_args: object, **_kwargs: object) -> object:
        pytest.fail("replacement API must not start after authority identity drift")

    monkeypatch.setattr(
        e2e_runtime,
        "_read_private_regular_file",
        swap_after_descriptor_open,
    )
    monkeypatch.setattr(e2e_runtime.subprocess, "Popen", reject_api_start)
    try:
        with pytest.raises(RuntimeError, match="private release authority validation failed"):
            lifecycle.start_api(resources)
        assert swapped is True
        assert displaced.is_dir()
    finally:
        for directory in (active, substitute, displaced):
            if directory.exists():
                shutil.rmtree(directory)
        resources.release_authority_directory = None
        resources.release_authority_directory_identity = None
        resources.release_authority_environment.clear()
        resources.release_reviewed_records = ()
        lifecycle.begin_cleanup()
        lifecycle.cleanup_private_output(resources)


def test_phase3_runtime_accepts_only_one_complete_private_browser_handoff() -> None:
    supplied = {
        capability: f"synthetic-browser-handoff-{capability}" for capability in PHASE3_CAPABILITIES
    }
    environment = OFFLINE_ENVIRONMENT | {
        f"ITDA_E2E_PHASE3_{capability.upper()}_CAPABILITY": value
        for capability, value in supplied.items()
    }

    resources = e2e_runtime.DefaultRuntimeLifecycle(environment).allocate()

    assert resources.phase3_capabilities == supplied
    assert all(
        raw not in e2e_runtime._safe_environment(environment).values() for raw in supplied.values()
    )


def test_phase3_migration_receives_every_exact_label_role_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import psycopg

    class FakeConnection:
        def __enter__(self) -> FakeConnection:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def execute(self, *args: object, **kwargs: object) -> None:
            return None

    lifecycle = e2e_runtime.DefaultRuntimeLifecycle(
        OFFLINE_ENVIRONMENT | {"ITDA_E2E_RUN_ID": "phase3-migration"}
    )
    resources = lifecycle.allocate()
    monkeypatch.setattr(psycopg, "connect", lambda *args, **kwargs: FakeConnection())
    captured: dict[str, object] = {}

    def record_startup(command: Sequence[str], **kwargs: object) -> None:
        captured["command"] = command
        captured.update(kwargs)

    monkeypatch.setattr(lifecycle, "_run_startup_process", record_startup)

    lifecycle.migrate(resources)

    environment = captured["environment"]
    assert isinstance(environment, Mapping)
    command = captured["command"]
    assert isinstance(command, Sequence)
    script = str(command[2])
    for capability in PHASE3_CAPABILITIES:
        environment_name = f"ITDA_LABEL_{capability.upper()}_ROLE"
        assert environment[environment_name] == resources.phase3_role_names[capability]
        assert (
            f'config.attributes["label_{capability}_role"] = os.environ["{environment_name}"]'
        ) in script


def test_phase3_test_support_is_e2e_only_and_revokes_the_requesting_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    normal_paths = create_app().openapi()["paths"]
    assert not any(path.startswith("/internal/test-support/phase3") for path in normal_paths)

    raw_capability = "synthetic-capability-never-persisted"
    monkeypatch.setenv("ITDA_E2E_PHASE3_TEST_SUPPORT", "1")
    monkeypatch.setenv(
        "ITDA_PHASE3_EVALUATOR_A_CAPABILITY_SHA256",
        hashlib.sha256(raw_capability.encode("utf-8")).hexdigest(),
    )
    monkeypatch.setenv(
        "ITDA_PHASE3_EVALUATOR_A_DATABASE_URL",
        "postgresql://synthetic-redacted@127.0.0.1:1/synthetic",
    )
    application = create_app()
    headers = {"X-ITDA-Phase3-Capability": raw_capability}

    with TestClient(application) as client:
        e2e_paths = application.openapi()["paths"]
        assert "/internal/test-support/phase3/revoke-self" in e2e_paths

        base_fixture = client.get(
            "/internal/test-support/phase3/fixture",
            headers=headers,
        )
        namespaced_fixture = client.get(
            "/internal/test-support/phase3/fixture?attempt=r0-e1-w2",
            headers=headers,
        )
        invalid_namespace = client.get(
            "/internal/test-support/phase3/fixture?attempt=../../private",
            headers=headers,
        )

        revoked = client.post(
            "/internal/test-support/phase3/revoke-self",
            headers=headers,
        )
        denied = client.post(
            "/internal/test-support/phase3/revoke-self",
            headers=headers,
        )

    assert base_fixture.status_code == 200
    assert base_fixture.json()["assignment"]["assignment_id"] == (
        "synthetic-runtime-assignment-alpha"
    )
    assert namespaced_fixture.status_code == 200
    assert namespaced_fixture.json()["assignment"]["assignment_id"] == (
        "synthetic-runtime-assignment-alpha-r0-e1-w2"
    )
    assert invalid_namespace.status_code == 422
    assert revoked.status_code == 204
    assert denied.status_code == 401
    assert raw_capability not in repr(application)
    assert raw_capability not in denied.text


def test_postgres_readiness_uses_named_300_second_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import psycopg

    clock = FakeClock()
    lifecycle = e2e_runtime.DefaultRuntimeLifecycle(
        OFFLINE_ENVIRONMENT,
        clock=clock.monotonic,
        sleep=clock.sleep,
    )
    monkeypatch.setattr(lifecycle, "_run_startup_process", lambda *args, **kwargs: None)

    def reject_connection(*args: object, **kwargs: object) -> object:
        raise psycopg.OperationalError("not ready")

    monkeypatch.setattr(psycopg, "connect", reject_connection)

    with pytest.raises(TimeoutError, match="within 300 seconds"):
        lifecycle.compose_up(runtime_resources())

    assert clock.now == e2e_runtime.POSTGRES_READY_TIMEOUT_SECONDS


def test_api_readiness_uses_named_300_second_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = FakeClock()
    lifecycle = e2e_runtime.DefaultRuntimeLifecycle(
        OFFLINE_ENVIRONMENT,
        clock=clock.monotonic,
        sleep=clock.sleep,
    )
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    monkeypatch.setattr(
        e2e_runtime.urllib.request,
        "urlopen",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            e2e_runtime.urllib.error.URLError("not ready")
        ),
    )
    try:
        with pytest.raises(TimeoutError, match="within 300 seconds"):
            lifecycle.wait_ready(runtime_resources(), process)
    finally:
        process.terminate()
        process.wait(timeout=5)

    assert clock.now == e2e_runtime.API_READY_TIMEOUT_SECONDS


def test_owned_startup_process_stops_immediately_when_cancelled() -> None:
    lifecycle = e2e_runtime.DefaultRuntimeLifecycle(OFFLINE_ENVIRONMENT)
    stop_requested = e2e_runtime.threading.Event()
    stop_requested.set()
    lifecycle.set_stop_event(stop_requested)

    started = time.monotonic()
    with pytest.raises(e2e_runtime.StartupCancelled):
        lifecycle._run_startup_process(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            environment=os.environ,
            timeout=e2e_runtime.MIGRATION_TIMEOUT_SECONDS,
        )

    assert time.monotonic() - started < 5


def test_supervisor_preflights_before_resource_allocation() -> None:
    lifecycle = RecordingLifecycle()

    def reject_preflight(*, environment: Mapping[str, str]) -> object:
        assert environment == OFFLINE_ENVIRONMENT
        raise e2e_runtime.PreflightError("blocked")

    with pytest.raises(e2e_runtime.PreflightError, match="blocked"):
        e2e_runtime.run_supervisor(
            environment=OFFLINE_ENVIRONMENT,
            lifecycle=lifecycle,
            preflight_check=reject_preflight,
        )

    assert lifecycle.events == []
    assert lifecycle.allocated is False


@pytest.mark.parametrize(
    ("fail_at", "expected_suffix"),
    [
        ("compose_up", ["cleanup_private_output", "compose_down"]),
        (
            "migrate",
            ["cleanup_private_output", "drop_database_and_role", "compose_down"],
        ),
        (
            "verify_runtime_role",
            ["cleanup_private_output", "drop_database_and_role", "compose_down"],
        ),
        (
            "start_api",
            ["cleanup_private_output", "drop_database_and_role", "compose_down"],
        ),
        (
            "wait_ready",
            [
                "stop_api",
                "cleanup_private_output",
                "drop_database_and_role",
                "compose_down",
            ],
        ),
        (
            "wait_until_stopped",
            [
                "stop_api",
                "cleanup_private_output",
                "drop_database_and_role",
                "compose_down",
            ],
        ),
    ],
)
def test_supervisor_cleans_every_started_layer_in_order(
    fail_at: str, expected_suffix: list[str]
) -> None:
    lifecycle = RecordingLifecycle(fail_at=fail_at)

    with pytest.raises(RuntimeError, match=f"{fail_at} failed"):
        e2e_runtime.run_supervisor(
            environment=OFFLINE_ENVIRONMENT,
            lifecycle=lifecycle,
            preflight_check=lambda *, environment: object(),
        )

    assert lifecycle.events[-len(expected_suffix) :] == expected_suffix


def test_supervisor_success_stops_api_before_database_and_compose() -> None:
    lifecycle = RecordingLifecycle()

    e2e_runtime.run_supervisor(
        environment=OFFLINE_ENVIRONMENT,
        lifecycle=lifecycle,
        preflight_check=lambda *, environment: object(),
    )

    assert lifecycle.events[-4:] == [
        "stop_api",
        "cleanup_private_output",
        "drop_database_and_role",
        "compose_down",
    ]


def test_label_freeze_output_allocate_failure_removes_private_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    created = tmp_path / "runtime-owned"
    quarantine = tmp_path / "quarantine-owned"

    def make_private_directory(*, prefix: str) -> str:
        target = quarantine if prefix.startswith("itda-phase6-quarantine-") else created
        target.mkdir(mode=0o700)
        return str(target)

    monkeypatch.setattr(e2e_runtime.tempfile, "mkdtemp", make_private_directory)
    monkeypatch.setattr(
        e2e_runtime,
        "_validate_label_freeze_output",
        lambda _resources: (_ for _ in ()).throw(RuntimeError("allocation validation failed")),
    )

    with pytest.raises(RuntimeError, match="allocation validation failed"):
        e2e_runtime.DefaultRuntimeLifecycle(OFFLINE_ENVIRONMENT).allocate()

    assert not created.exists()
    assert not quarantine.exists()


def test_label_freeze_output_cleanup_is_parallel_isolated_and_symlink_safe(
    tmp_path: Path,
) -> None:
    first_lifecycle = e2e_runtime.DefaultRuntimeLifecycle(
        OFFLINE_ENVIRONMENT | {"ITDA_E2E_RUN_ID": "parallel"}
    )
    second_lifecycle = e2e_runtime.DefaultRuntimeLifecycle(
        OFFLINE_ENVIRONMENT | {"ITDA_E2E_RUN_ID": "parallel"}
    )
    first = first_lifecycle.allocate()
    second = second_lifecycle.allocate()
    external = tmp_path / "external-target"
    external.write_bytes(b"byte-identical")
    first.label_freeze_output.symlink_to(external)
    second.label_freeze_output.write_bytes(b"second-runtime")

    try:
        first_lifecycle.cleanup_private_output(first)

        assert not first.label_freeze_directory.exists()
        assert external.read_bytes() == b"byte-identical"
        assert second.label_freeze_directory.is_dir()
        assert second.label_freeze_output.read_bytes() == b"second-runtime"

        second_lifecycle.cleanup_private_output(second)
        second_lifecycle.cleanup_private_output(second)
        assert not second.label_freeze_directory.exists()
    finally:
        if first.label_freeze_directory.exists():
            _remove_test_freeze_output(first)
        if second.label_freeze_directory.exists():
            _remove_test_freeze_output(second)


def test_label_freeze_output_cleanup_preserves_primary_error_and_redacts_paths() -> None:
    lifecycle = RecordingLifecycle(fail_at="wait_ready", cleanup_fails=True)

    with pytest.raises(RuntimeError, match="wait_ready failed") as captured:
        e2e_runtime.run_supervisor(
            environment=OFFLINE_ENVIRONMENT,
            lifecycle=lifecycle,
            preflight_check=lambda *, environment: object(),
        )

    assert "private output cleanup failed" in " ".join(captured.value.__notes__)
    assert lifecycle.events[-4:] == [
        "stop_api",
        "cleanup_private_output",
        "drop_database_and_role",
        "compose_down",
    ]


@pytest.mark.parametrize("signal_name", ["SIGINT", "SIGTERM"])
def test_label_freeze_output_cleanup_runs_for_signal_driven_startup_unwind(
    signal_name: str,
) -> None:
    class SignalLifecycle(RecordingLifecycle):
        def compose_up(self, resources: object) -> None:
            super().compose_up(resources)
            signal.raise_signal(getattr(signal, signal_name))

    lifecycle = SignalLifecycle()

    with pytest.raises(e2e_runtime.StartupCancelled):
        e2e_runtime.run_supervisor(
            environment=OFFLINE_ENVIRONMENT,
            lifecycle=lifecycle,
            preflight_check=lambda *, environment: object(),
        )

    assert lifecycle.events[-2:] == ["cleanup_private_output", "compose_down"]


@pytest.mark.parametrize(
    ("returncode", "marker_seen", "expected_error"),
    [
        (1, True, None),
        (1, False, "before marker"),
        (0, True, "unexpectedly passed"),
    ],
)
def test_intentional_failure_requires_unique_marker_and_nonzero_exit(
    returncode: int,
    marker_seen: bool,
    expected_error: str | None,
) -> None:
    if expected_error is None:
        e2e_runtime._validate_completed_lifecycle(
            mode="intentional-failure",
            returncode=returncode,
            intentional_failure_marker_seen=marker_seen,
            output="",
        )
        return
    with pytest.raises(RuntimeError, match=expected_error):
        e2e_runtime._validate_completed_lifecycle(
            mode="intentional-failure",
            returncode=returncode,
            intentional_failure_marker_seen=marker_seen,
            output="",
        )


def test_intentional_failure_spec_emits_marker_before_deliberate_assertion() -> None:
    source = (WEB_ROOT / "e2e" / "runtime-lifecycle.spec.ts").read_text(encoding="utf-8")
    marker_position = source.index(e2e_runtime.LIFECYCLE_INTENTIONAL_FAILURE_MARKER)
    assertion_position = source.index('page.getByText("intentional lifecycle failure sentinel")')

    assert marker_position < assertion_position


def test_database_timeouts_are_bounded_and_reserve_compose_down() -> None:
    assert e2e_runtime.DATABASE_CONNECT_TIMEOUT_SECONDS == 3
    assert e2e_runtime.DATABASE_STATEMENT_TIMEOUT_MS == 5_000
    assert e2e_runtime.DATABASE_LOCK_TIMEOUT_MS == 3_000
    assert "statement_timeout=5000" in e2e_runtime.DATABASE_SESSION_OPTIONS
    assert "lock_timeout=3000" in e2e_runtime.DATABASE_SESSION_OPTIONS

    clock = FakeClock()
    lifecycle = e2e_runtime.DefaultRuntimeLifecycle(
        OFFLINE_ENVIRONMENT,
        clock=clock.monotonic,
        sleep=clock.sleep,
    )
    lifecycle.begin_cleanup()
    clock.now = e2e_runtime.CLEANUP_BUDGET_SECONDS - (e2e_runtime.COMPOSE_DOWN_RESERVED_SECONDS + 1)
    assert lifecycle._database_cleanup_timeout(5) == 1
    assert (
        lifecycle._cleanup_timeout(e2e_runtime.COMPOSE_DOWN_RESERVED_SECONDS)
        == e2e_runtime.COMPOSE_DOWN_RESERVED_SECONDS
    )
    clock.now += 1
    with pytest.raises(TimeoutError, match="reserving"):
        lifecycle._database_cleanup_timeout(1)
    assert (
        lifecycle._cleanup_timeout(e2e_runtime.COMPOSE_DOWN_RESERVED_SECONDS)
        == e2e_runtime.COMPOSE_DOWN_RESERVED_SECONDS
    )


def test_lifecycle_gate_runs_success_expected_failure_and_startup_interruptions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str | None, str]] = []

    def record_mode(
        *,
        mode: str,
        run_id: str,
        environment: Mapping[str, str],
        interrupt_phase: str | None = None,
    ) -> None:
        assert environment == OFFLINE_ENVIRONMENT
        calls.append((mode, interrupt_phase, run_id))

    monkeypatch.setattr(e2e_runtime, "_run_lifecycle_mode", record_mode)

    e2e_runtime.run_lifecycle_gate(environment=OFFLINE_ENVIRONMENT)

    assert [(mode, phase) for mode, phase, _ in calls] == [
        ("success", None),
        ("intentional-failure", None),
        ("wait-for-interruption", "compose-readiness"),
        ("wait-for-interruption", "migration"),
        ("wait-for-interruption", None),
    ]
    assert len({run_id for _, _, run_id in calls}) == len(calls)


@pytest.mark.parametrize(
    ("phase", "expected_sentinel"),
    [
        ("compose-readiness", "ITDA_E2E_COMPOSE_RESOURCE_ACTIVE"),
        ("migration", "ITDA_E2E_MIGRATION_WORK_ACTIVE"),
        (None, "ITDA_E2E_READY_FOR_INTERRUPTION"),
    ],
)
def test_each_interruption_phase_requires_its_exact_sentinel(
    phase: str | None, expected_sentinel: str
) -> None:
    assert e2e_runtime.LIFECYCLE_INTERRUPT_SENTINELS[phase] == expected_sentinel


def test_interruption_sentinel_budget_covers_compose_before_migration() -> None:
    assert e2e_runtime._interruption_sentinel_timeout("compose-readiness") == (
        e2e_runtime.PREFLIGHT_TIMEOUT_SECONDS
        + e2e_runtime.COMPOSE_UP_TIMEOUT_SECONDS
        + e2e_runtime.COMPOSE_ACTIVE_PROBE_TIMEOUT_SECONDS
    )
    assert e2e_runtime._interruption_sentinel_timeout(
        "migration"
    ) == e2e_runtime.PREFLIGHT_TIMEOUT_SECONDS + sum(
        (
            e2e_runtime.COMPOSE_UP_TIMEOUT_SECONDS,
            e2e_runtime.POSTGRES_READY_TIMEOUT_SECONDS,
            e2e_runtime.MIGRATION_TIMEOUT_SECONDS,
        )
    )
    assert (
        e2e_runtime._interruption_sentinel_timeout(None)
        == e2e_runtime.LIFECYCLE_MODE_TIMEOUT_SECONDS
    )


def test_outer_lifecycle_deadline_covers_every_named_sequential_budget() -> None:
    clock = FakeClock()
    deadline = (
        clock.monotonic()
        + sum(e2e_runtime.LIFECYCLE_SEQUENTIAL_STARTUP_BUDGETS)
        + e2e_runtime.LIFECYCLE_TEARDOWN_MARGIN_SECONDS
    )

    for budget in e2e_runtime.LIFECYCLE_SEQUENTIAL_STARTUP_BUDGETS:
        clock.sleep(budget - e2e_runtime.STARTUP_POLL_SECONDS)
        assert clock.monotonic() < deadline
        clock.sleep(e2e_runtime.STARTUP_POLL_SECONDS)

    clock.sleep(e2e_runtime.LIFECYCLE_TEARDOWN_MARGIN_SECONDS - e2e_runtime.STARTUP_POLL_SECONDS)
    assert clock.monotonic() < deadline
    clock.sleep(e2e_runtime.STARTUP_POLL_SECONDS)
    assert clock.monotonic() == deadline
    assert (
        sum(e2e_runtime.LIFECYCLE_SEQUENTIAL_STARTUP_BUDGETS)
        + e2e_runtime.LIFECYCLE_TEARDOWN_MARGIN_SECONDS
        == e2e_runtime.LIFECYCLE_MODE_TIMEOUT_SECONDS
    )


def test_preflight_budget_models_every_sequential_probe() -> None:
    assert (
        len(e2e_runtime._PINNED_TOOLS) * len(e2e_runtime.PINNED_TOOL_PREFLIGHT_PROBES)
        == e2e_runtime.PINNED_TOOL_PREFLIGHT_PROBE_COUNT
    )
    assert len(e2e_runtime.DOCKER_PREFLIGHT_PROBES) == e2e_runtime.DOCKER_PREFLIGHT_PROBE_COUNT
    assert len(e2e_runtime.LONG_PREFLIGHT_PROBES) == e2e_runtime.LONG_PREFLIGHT_PROBE_COUNT
    assert e2e_runtime.PREFLIGHT_TIMEOUT_SECONDS == (
        (e2e_runtime.PINNED_TOOL_PREFLIGHT_PROBE_COUNT + e2e_runtime.DOCKER_PREFLIGHT_PROBE_COUNT)
        * e2e_runtime.DEFAULT_PREREQUISITE_TIMEOUT_SECONDS
        + e2e_runtime.LONG_PREFLIGHT_PROBE_COUNT * e2e_runtime.PREREQUISITE_TIMEOUT_SECONDS
    )


@pytest.mark.parametrize(
    "sentinel",
    [
        "ITDA_E2E_COMPOSE_RESOURCE_ACTIVE",
        "ITDA_E2E_MIGRATION_WORK_ACTIVE",
    ],
)
def test_playwright_webserver_transport_preserves_exact_sentinel_payload(
    sentinel: str,
) -> None:
    transported = f"\x1b[2m[WebServer] \x1b[22m{sentinel}\x1b[0m\n"

    assert e2e_runtime._matches_lifecycle_marker(transported, sentinel)
    assert e2e_runtime._matches_lifecycle_marker(f"{sentinel}\n", sentinel)


def test_playwright_transport_accepts_only_one_recognized_configured_prefix() -> None:
    sentinel = "ITDA_E2E_MIGRATION_WORK_ACTIVE"
    configured = f"\x1b[2m[ITDA Backend] \x1b[22m{sentinel}\n"

    assert e2e_runtime._matches_lifecycle_marker(
        configured,
        sentinel,
        web_server_names=("ITDA Backend",),
    )
    assert not e2e_runtime._matches_lifecycle_marker(
        f"[ITDA Backend] [ITDA Backend] {sentinel}",
        sentinel,
        web_server_names=("ITDA Backend",),
    )


@pytest.mark.parametrize(
    "transported",
    [
        "noise ITDA_E2E_COMPOSE_RESOURCE_ACTIVE",
        "[WebServer] before ITDA_E2E_COMPOSE_RESOURCE_ACTIVE",
        "[WebServer] ITDA_E2E_COMPOSE_RESOURCE_ACTIVE after",
        "[Unknown] ITDA_E2E_COMPOSE_RESOURCE_ACTIVE",
        "[WebServer] [WebServer] ITDA_E2E_COMPOSE_RESOURCE_ACTIVE",
        "[WebServer]  ITDA_E2E_COMPOSE_RESOURCE_ACTIVE",
        "[WebServer] ITDA_E2E_COMPOSE_RESOURCE_ACTIVE ",
    ],
)
def test_playwright_transport_rejects_arbitrary_sentinel_substrings(
    transported: str,
) -> None:
    assert not e2e_runtime._matches_lifecycle_marker(
        transported,
        "ITDA_E2E_COMPOSE_RESOURCE_ACTIVE",
    )


def test_identifier_fragment_preserves_uniqueness_for_long_run_ids() -> None:
    first = "interrupt_compose_readiness_12345_deadbeef"
    second = "interrupt_compose_readiness_12345_feedface"

    first_fragment = e2e_runtime._identifier_fragment(first)
    second_fragment = e2e_runtime._identifier_fragment(second)

    assert len(first_fragment) == 20
    assert len(second_fragment) == 20
    assert first_fragment == e2e_runtime._identifier_fragment(first)
    assert first_fragment != second_fragment


def test_residue_detection_does_not_cross_match_long_run_id_hashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = "interrupt_compose_readiness_12345_deadbeef"
    second = "interrupt_compose_readiness_12345_feedface"
    second_project = f"itda_e2e_{e2e_runtime._identifier_fragment(second)}_4321_cafebabe"
    monkeypatch.setattr(
        e2e_runtime.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "", ""),
    )
    monkeypatch.setattr(
        e2e_runtime,
        "_docker_json_rows",
        lambda *args, **kwargs: [{"name": second_project, "project": second_project}],
    )

    e2e_runtime.assert_no_runtime_residue(first, environment=OFFLINE_ENVIRONMENT)
    with pytest.raises(RuntimeError, match="lifecycle residue detected"):
        e2e_runtime.assert_no_runtime_residue(
            second,
            environment=OFFLINE_ENVIRONMENT,
        )


def test_residue_inspection_parenthesizes_label_lookup_for_docker_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[tuple[str, ...]] = []

    def record_command(
        command: Sequence[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        vector = tuple(command)
        commands.append(vector)
        return subprocess.CompletedProcess(vector, 0, "", "")

    monkeypatch.setattr(e2e_runtime.subprocess, "run", record_command)

    e2e_runtime.assert_no_runtime_residue(
        "success_12345_deadbeef",
        environment=OFFLINE_ENVIRONMENT,
    )

    custom_formats = [
        command[command.index("--format") + 1]
        for command in commands
        if command[:3] != ("docker", "compose", "ls") and "--format" in command
    ]
    assert custom_formats == [
        ('{"name":{{json .Names}},"project":{{json (.Label "com.docker.compose.project")}}}'),
        ('{"name":{{json .Name}},"project":{{json (.Label "com.docker.compose.project")}}}'),
        ('{"name":{{json .Name}},"project":{{json (.Label "com.docker.compose.project")}}}'),
    ]


def test_startup_sentinel_requires_exact_child_work_marker(
    capsys: pytest.CaptureFixture[str],
) -> None:
    lifecycle = e2e_runtime.DefaultRuntimeLifecycle(OFFLINE_ENVIRONMENT)
    lifecycle._run_startup_process(
        [
            sys.executable,
            "-c",
            f"print({e2e_runtime.MIGRATION_CHILD_WORK_MARKER!r}, flush=True)",
        ],
        environment=os.environ,
        timeout=5,
        started_sentinel=e2e_runtime.LIFECYCLE_INTERRUPT_SENTINELS["migration"],
        child_work_marker=e2e_runtime.MIGRATION_CHILD_WORK_MARKER,
    )

    assert capsys.readouterr().out.strip() == e2e_runtime.LIFECYCLE_INTERRUPT_SENTINELS["migration"]


def test_compose_sentinel_requires_running_postgres_resource(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import psycopg

    class ReadyConnection:
        def __enter__(self) -> ReadyConnection:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def execute(self, *args: object, **kwargs: object) -> ReadyConnection:
            return self

        def fetchone(self) -> tuple[int]:
            return (170_010,)

    environment = {
        **OFFLINE_ENVIRONMENT,
        "ITDA_E2E_INTERRUPT_PHASE": "compose-readiness",
    }
    lifecycle = e2e_runtime.DefaultRuntimeLifecycle(environment)
    monkeypatch.setattr(lifecycle, "_run_startup_process", lambda *args, **kwargs: None)
    compose_calls: list[Sequence[str]] = []

    def compose_result(
        _resources: e2e_runtime.RuntimeResources,
        arguments: Sequence[str],
        *,
        timeout: float,
    ) -> str:
        assert timeout <= e2e_runtime.POSTGRES_READY_TIMEOUT_SECONDS
        compose_calls.append(arguments)
        return "container-id"

    monkeypatch.setattr(lifecycle, "_compose", compose_result)
    monkeypatch.setattr(psycopg, "connect", lambda *args, **kwargs: ReadyConnection())

    lifecycle.compose_up(runtime_resources())

    assert compose_calls == [["ps", "--status", "running", "--quiet", "postgres"]]
    assert (
        capsys.readouterr().out.strip()
        == e2e_runtime.LIFECYCLE_INTERRUPT_SENTINELS["compose-readiness"]
    )


def test_migration_marker_follows_live_alembic_connection_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import psycopg

    class FakeConnection:
        def __enter__(self) -> FakeConnection:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def execute(self, *args: object, **kwargs: object) -> None:
            return None

    environment = {
        **OFFLINE_ENVIRONMENT,
        "ITDA_E2E_INTERRUPT_PHASE": "migration",
    }
    lifecycle = e2e_runtime.DefaultRuntimeLifecycle(environment)
    monkeypatch.setattr(psycopg, "connect", lambda *args, **kwargs: FakeConnection())
    captured: dict[str, object] = {}

    def record_startup(command: Sequence[str], **kwargs: object) -> None:
        captured["command"] = command
        captured.update(kwargs)

    monkeypatch.setattr(lifecycle, "_run_startup_process", record_startup)
    lifecycle.migrate(runtime_resources())

    command = captured["command"]
    assert isinstance(command, Sequence)
    script = str(command[2])
    assert script.index("MigrationContext.configure") < script.index(
        e2e_runtime.MIGRATION_CHILD_WORK_MARKER
    )
    assert captured["child_work_marker"] == e2e_runtime.MIGRATION_CHILD_WORK_MARKER
    assert captured["started_sentinel"] == e2e_runtime.LIFECYCLE_INTERRUPT_SENTINELS["migration"]


def test_migration_script_preserves_percent_encoded_database_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import psycopg

    from itda.db.session import sqlalchemy_url_from_dsn

    class FakeConnection:
        def __enter__(self) -> FakeConnection:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def execute(self, *args: object, **kwargs: object) -> None:
            return None

    resources = replace(
        runtime_resources(),
        admin_dsn=(
            "postgresql://admin:admin@127.0.0.1:54327/itda_e2e_test"
            "?options=-c%20statement_timeout%3D5000"
        ),
    )
    lifecycle = e2e_runtime.DefaultRuntimeLifecycle(OFFLINE_ENVIRONMENT)
    monkeypatch.setattr(psycopg, "connect", lambda *args, **kwargs: FakeConnection())
    captured: dict[str, object] = {}

    def record_startup(command: Sequence[str], **kwargs: object) -> None:
        captured["command"] = command
        captured.update(kwargs)

    monkeypatch.setattr(lifecycle, "_run_startup_process", record_startup)
    lifecycle.migrate(resources)

    command = captured["command"]
    assert isinstance(command, Sequence)
    script = str(command[2])
    config_boundary, separator, _ = script.partition('config.attributes["runtime_role"]')
    assert separator
    probe_script = config_boundary + '\nprint(config.get_main_option("sqlalchemy.url"), flush=True)'
    environment = captured["environment"]
    assert isinstance(environment, Mapping)
    result = subprocess.run(
        [sys.executable, "-c", probe_script],
        cwd=e2e_runtime.BACKEND_ROOT,
        env=dict(environment),
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == sqlalchemy_url_from_dsn(resources.admin_dsn).render_as_string(
        hide_password=False
    )


def test_process_group_members_ignore_zombies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def process_table(
        command: Sequence[str],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        assert list(command) == ["ps", "-axo", "pid=,pgid=,state="]
        return subprocess.CompletedProcess(
            command,
            0,
            "4242 4242 Z\n4243 4242 S\n4244 4300 R\n4245 4242 ?\n",
            "",
        )

    monkeypatch.setattr(e2e_runtime.subprocess, "run", process_table)

    assert e2e_runtime._process_group_pids(4242) == (4243, 4245)


def test_process_group_extinction_escalates_surviving_descendants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @dataclass
    class FakeProcess:
        pid: int = 4242
        returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

    clock = FakeClock()
    signals: list[signal.Signals] = []
    process = FakeProcess()
    monkeypatch.setattr(
        e2e_runtime.os,
        "killpg",
        lambda _pgid, sent_signal: signals.append(sent_signal),
    )
    monkeypatch.setattr(
        e2e_runtime,
        "_process_group_pids",
        lambda _pgid: () if signals[-1:] == [signal.SIGKILL] else (process.pid, 4243),
    )

    escalated = e2e_runtime._terminate_process_group(
        process,  # type: ignore[arg-type]
        grace_seconds=0.5,
        clock=clock.monotonic,
        sleep=clock.sleep,
    )

    assert escalated is True
    assert signals == [signal.SIGTERM, signal.SIGKILL]


def test_process_group_extinction_reaps_exited_root_before_signalling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    polls: list[int] = []

    @dataclass
    class FakeProcess:
        pid: int = 4242

        def poll(self) -> int:
            polls.append(self.pid)
            return -signal.SIGTERM

    monkeypatch.setattr(e2e_runtime, "_process_group_pids", lambda _pgid: ())
    monkeypatch.setattr(
        e2e_runtime.os,
        "killpg",
        lambda *_args: pytest.fail("extinct process group was signalled"),
    )

    assert e2e_runtime._terminate_process_group(FakeProcess()) is False
    assert polls == [4242]


def _owned_backend_rows(
    run_id: str,
    process_group_id: int = 5100,
) -> tuple[e2e_runtime._ProcessTableRow, ...]:
    run_token = f"ITDA_E2E_RUN_ID={run_id}"
    return (
        e2e_runtime._ProcessTableRow(
            5101,
            process_group_id,
            f"make e2e-backend {run_token}",
        ),
        e2e_runtime._ProcessTableRow(
            5102,
            process_group_id,
            f"python -m itda.cli.e2e_runtime {run_token}",
        ),
    )


@pytest.mark.parametrize(
    ("case", "error"),
    [
        ("mixed", "mixed ownership"),
        ("current", "refusing excluded"),
        ("outer", "refusing excluded"),
        ("ambiguous", "exactly one"),
    ],
)
def test_run_owned_backend_process_group_refuses_unsafe_candidates(
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    error: str,
) -> None:
    run_id = "interrupt_compose_readiness_regression"
    candidate_pgid = 4000 if case == "current" else 4200 if case == "outer" else 5100
    rows = _owned_backend_rows(run_id, candidate_pgid)
    if case == "mixed":
        rows += (e2e_runtime._ProcessTableRow(5103, candidate_pgid, "unrelated-worker"),)
    elif case == "ambiguous":
        rows += _owned_backend_rows(run_id, 5200)
    monkeypatch.setattr(e2e_runtime, "_process_table_rows", lambda: rows)
    monkeypatch.setattr(e2e_runtime.os, "getpgrp", lambda: 4000)

    with pytest.raises(RuntimeError, match=error):
        e2e_runtime._run_owned_backend_process_group_id(
            run_id,
            outer_process_group_id=4200,
        )


def test_run_owned_backend_process_group_selects_only_exact_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = "interrupt_compose_readiness_regression"
    rows = _owned_backend_rows(run_id) + (
        e2e_runtime._ProcessTableRow(9000, 9000, "unrelated-worker"),
    )
    monkeypatch.setattr(e2e_runtime, "_process_table_rows", lambda: rows)
    monkeypatch.setattr(e2e_runtime.os, "getpgrp", lambda: 4000)

    assert (
        e2e_runtime._run_owned_backend_process_group_id(
            run_id,
            outer_process_group_id=4200,
        )
        == 5100
    )


def _owned_frontend_rows(
    run_id: str,
    process_group_id: int = 6100,
) -> tuple[e2e_runtime._ProcessTableRow, ...]:
    run_token = f"ITDA_E2E_RUN_ID={run_id}"
    return (
        e2e_runtime._ProcessTableRow(
            6101,
            process_group_id,
            f"pnpm dev -H 127.0.0.1 -p 5173 {run_token}",
        ),
        e2e_runtime._ProcessTableRow(
            6102,
            process_group_id,
            (
                "node /repo/web/node_modules/.bin/../next/dist/bin/next dev "
                f"-H 127.0.0.1 -p 5173 {run_token}"
            ),
        ),
    )


@pytest.mark.parametrize(
    ("case", "error"),
    [
        ("mixed", "mixed ownership"),
        ("current", "refusing excluded"),
        ("outer", "refusing excluded"),
        ("ambiguous", "exactly one"),
    ],
)
def test_run_owned_frontend_process_group_refuses_unsafe_candidates(
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    error: str,
) -> None:
    run_id = "interrupt_ready_regression"
    candidate_pgid = 4000 if case == "current" else 4200 if case == "outer" else 6100
    rows = _owned_frontend_rows(run_id, candidate_pgid)
    if case == "mixed":
        rows += (
            e2e_runtime._ProcessTableRow(
                6103,
                candidate_pgid,
                "unrelated-worker",
            ),
        )
    elif case == "ambiguous":
        rows += _owned_frontend_rows(run_id, 6200)
    monkeypatch.setattr(e2e_runtime, "_process_table_rows", lambda: rows)
    monkeypatch.setattr(e2e_runtime.os, "getpgrp", lambda: 4000)

    with pytest.raises(RuntimeError, match=error):
        e2e_runtime._run_owned_frontend_process_group_id(
            run_id,
            outer_process_group_id=4200,
        )


def test_run_owned_frontend_process_group_selects_only_exact_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = "interrupt_ready_regression"
    rows = _owned_frontend_rows(run_id) + (
        e2e_runtime._ProcessTableRow(9000, 9000, "unrelated-worker"),
    )
    monkeypatch.setattr(e2e_runtime, "_process_table_rows", lambda: rows)
    monkeypatch.setattr(e2e_runtime.os, "getpgrp", lambda: 4000)

    assert (
        e2e_runtime._run_owned_frontend_process_group_id(
            run_id,
            outer_process_group_id=4200,
        )
        == 6100
    )


def test_interrupt_lifecycle_reaps_playwright_before_residue_inspection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[str, object]] = []
    run_id = "interrupt_ready_regression"
    run_token = f"ITDA_E2E_RUN_ID={run_id}"
    process_rows = _owned_backend_rows(run_id) + (
        e2e_runtime._ProcessTableRow(
            6100,
            6100,
            " ".join((*e2e_runtime.FRONTEND_PROCESS_COMMAND, run_token)),
        ),
        e2e_runtime._ProcessTableRow(
            6101,
            6100,
            (
                "node /repo/web/node_modules/.bin/../next/dist/bin/next dev "
                f"-H 127.0.0.1 {run_token}"
            ),
        ),
    )

    @dataclass
    class FakeProcess:
        pid: int = 4242
        stdout: io.StringIO = field(
            default_factory=lambda: io.StringIO(
                f"{e2e_runtime.LIFECYCLE_INTERRUPT_SENTINELS[None]}\n"
            )
        )
        returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: float | None = None) -> int:
            events.append(("wait", timeout))
            if self.returncode is None:
                self.returncode = -signal.SIGINT
            return self.returncode

    process = FakeProcess()
    monkeypatch.setattr(
        e2e_runtime.subprocess,
        "Popen",
        lambda *args, **kwargs: process,
    )

    def terminate_outer(
        owned_process: subprocess.Popen[str],
        *,
        graceful_signal: signal.Signals = signal.SIGTERM,
        **_kwargs: object,
    ) -> bool:
        assert owned_process is process
        events.append(("terminate", graceful_signal))
        process.returncode = -int(graceful_signal)
        return False

    monkeypatch.setattr(e2e_runtime, "_terminate_process_group", terminate_outer)
    monkeypatch.setattr(e2e_runtime, "_process_group_pids", lambda _pgid: ())
    monkeypatch.setattr(
        e2e_runtime,
        "_process_table_rows",
        lambda: process_rows,
    )

    terminated_group_ids: list[int] = []

    def terminate_owned_group(
        process_group_id: int,
        *,
        graceful_signal: signal.Signals,
        **_kwargs: object,
    ) -> bool:
        terminated_group_ids.append(process_group_id)
        events.append(("owned-terminate", (process_group_id, graceful_signal)))
        return False

    monkeypatch.setattr(
        e2e_runtime,
        "_terminate_process_group_id",
        terminate_owned_group,
    )

    def assert_residue_reaped(
        asserted_run_id: str,
        *,
        environment: Mapping[str, str],
    ) -> None:
        assert asserted_run_id == run_id
        assert environment == OFFLINE_ENVIRONMENT
        if 6100 not in terminated_group_ids:
            raise RuntimeError("frontend residue reached assertion")
        events.append(("residue", asserted_run_id))

    monkeypatch.setattr(
        e2e_runtime,
        "assert_no_runtime_residue",
        assert_residue_reaped,
    )

    e2e_runtime._run_lifecycle_mode(
        mode="wait-for-interruption",
        run_id=run_id,
        environment=OFFLINE_ENVIRONMENT,
        interrupt_phase=None,
    )

    assert events == [
        ("owned-terminate", (5100, signal.SIGTERM)),
        ("owned-terminate", (6100, signal.SIGTERM)),
        ("terminate", signal.SIGINT),
        ("wait", None),
        ("residue", run_id),
    ]


@pytest.mark.parametrize("interrupt_phase", ["compose-readiness", "migration"])
def test_early_interrupt_lifecycle_does_not_require_frontend_group(
    monkeypatch: pytest.MonkeyPatch,
    interrupt_phase: str,
) -> None:
    events: list[tuple[str, object]] = []
    run_id = f"interrupt_{interrupt_phase.replace('-', '_')}_regression"

    @dataclass
    class FakeProcess:
        pid: int = 4242
        stdout: io.StringIO = field(
            default_factory=lambda: io.StringIO(
                f"{e2e_runtime.LIFECYCLE_INTERRUPT_SENTINELS[interrupt_phase]}\n"
            )
        )
        returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: float | None = None) -> int:
            events.append(("wait", timeout))
            if self.returncode is None:
                self.returncode = -signal.SIGINT
            return self.returncode

    process = FakeProcess()
    monkeypatch.setattr(
        e2e_runtime.subprocess,
        "Popen",
        lambda *args, **kwargs: process,
    )

    def terminate_outer(
        owned_process: subprocess.Popen[str],
        *,
        graceful_signal: signal.Signals = signal.SIGTERM,
        **_kwargs: object,
    ) -> bool:
        assert owned_process is process
        events.append(("terminate", graceful_signal))
        process.returncode = -int(graceful_signal)
        return False

    monkeypatch.setattr(e2e_runtime, "_terminate_process_group", terminate_outer)
    monkeypatch.setattr(e2e_runtime, "_process_group_pids", lambda _pgid: ())
    monkeypatch.setattr(
        e2e_runtime,
        "_process_table_rows",
        lambda: _owned_backend_rows(run_id),
    )

    def terminate_owned_group(
        process_group_id: int,
        *,
        graceful_signal: signal.Signals,
        **_kwargs: object,
    ) -> bool:
        events.append(("owned-terminate", (process_group_id, graceful_signal)))
        return False

    monkeypatch.setattr(
        e2e_runtime,
        "_terminate_process_group_id",
        terminate_owned_group,
    )
    monkeypatch.setattr(
        e2e_runtime,
        "assert_no_runtime_residue",
        lambda asserted_run_id, *, environment: events.append(("residue", asserted_run_id)),
    )

    e2e_runtime._run_lifecycle_mode(
        mode="wait-for-interruption",
        run_id=run_id,
        environment=OFFLINE_ENVIRONMENT,
        interrupt_phase=interrupt_phase,
    )

    assert events == [
        ("owned-terminate", (5100, signal.SIGTERM)),
        ("terminate", signal.SIGINT),
        ("wait", None),
        ("residue", run_id),
    ]


@pytest.mark.parametrize(
    "run_id",
    [
        "success_12345_deadbeef",
        "failure_12345_deadbeef",
        "interrupt_compose_readiness_12345_deadbeef",
        "interrupt_migration_12345_deadbeef",
        "interrupt_ready_12345_deadbeef",
    ],
)
@pytest.mark.parametrize("leak_kind", ["compose", "container", "volume", "network"])
def test_residue_detection_uses_allocations_canonical_prefix_for_every_lifecycle_shape(
    monkeypatch: pytest.MonkeyPatch,
    run_id: str,
    leak_kind: str,
) -> None:
    run_fragment = e2e_runtime._identifier_fragment(run_id)
    expected_prefix = f"itda_e2e_{run_fragment}"

    monkeypatch.setattr(
        e2e_runtime.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0],
            0,
            "",
            "",
        ),
    )

    def synthetic_rows(
        command: Sequence[str], *, environment: Mapping[str, str]
    ) -> list[dict[str, object]]:
        assert environment
        if command[:3] == ["docker", "compose", "ls"]:
            kind = "compose"
            row = {"Name": f"{expected_prefix}_4321_cafebabe"}
        elif command[:2] == ["docker", "ps"]:
            kind = "container"
            row = {
                "name": f"{expected_prefix}_4321_cafebabe-postgres-1",
                "project": f"{expected_prefix}_4321_cafebabe",
            }
        elif command[:3] == ["docker", "volume", "ls"]:
            kind = "volume"
            row = {
                "name": f"{expected_prefix}_4321_cafebabe_postgres-data",
                "project": f"{expected_prefix}_4321_cafebabe",
            }
        else:
            kind = "network"
            row = {
                "name": f"{expected_prefix}_4321_cafebabe_default",
                "project": f"{expected_prefix}_4321_cafebabe",
            }
        return [row] if kind == leak_kind else []

    monkeypatch.setattr(e2e_runtime, "_docker_json_rows", synthetic_rows)

    with pytest.raises(RuntimeError, match="lifecycle residue detected"):
        e2e_runtime.assert_no_runtime_residue(
            run_id,
            environment=OFFLINE_ENVIRONMENT,
        )


def test_diagnostics_redact_generated_secrets_and_provider_credentials() -> None:
    secrets = (
        "admin-secret",
        "runtime-secret",
        "postgresql://admin:admin-secret@127.0.0.1/db",
        os.environ.get("TOUR_API_KEY", ""),
    )
    diagnostic = " ".join(secret for secret in secrets if secret)

    redacted = e2e_runtime.redact_diagnostic(diagnostic, secrets)

    for secret in secrets:
        if secret:
            assert secret not in redacted
    assert "<redacted>" in redacted


def test_preflight_only_main_does_not_allocate_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        e2e_runtime,
        "preflight",
        lambda *, environment: calls.append("preflight"),
    )
    monkeypatch.setattr(
        e2e_runtime,
        "run_supervisor",
        lambda **_: calls.append("supervisor"),
    )

    assert e2e_runtime.main(["--preflight-only"], environment=OFFLINE_ENVIRONMENT) == 0
    assert calls == ["preflight"]


def port_is_bound(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.05)
        return probe.connect_ex(("127.0.0.1", port)) == 0


def run_failed_top_level_preflight(
    *,
    browser_path: Path,
    run_id: str,
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    assert not port_is_bound(8000)
    assert not port_is_bound(5173)
    environment = {
        **os.environ,
        **OFFLINE_ENVIRONMENT,
        "CI": "true",
        "ITDA_E2E_FRESH": "1",
        "ITDA_E2E_RUN_ID": run_id,
        "PLAYWRIGHT_BROWSERS_PATH": str(browser_path),
    }
    process = subprocess.Popen(
        ["make", "phase-01-uat"],
        cwd=REPO_ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    forbidden_processes: list[str] = []
    port_samples: list[tuple[bool, bool]] = []
    deadline = time.monotonic() + 240
    while process.poll() is None and time.monotonic() < deadline:
        port_samples.append((port_is_bound(8000), port_is_bound(5173)))
        process_table = subprocess.run(
            ["ps", "e", "-ax", "-o", "command="],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout
        for line in process_table.splitlines():
            if run_id not in line or "--preflight-only" in line:
                continue
            if any(
                token in line
                for token in ("playwright test", "next", "uvicorn", "itda.cli.e2e_runtime")
            ):
                forbidden_processes.append(line)
        time.sleep(0.05)

    if process.poll() is None:
        os.killpg(process.pid, 15)
        process.wait(timeout=15)
        raise AssertionError("top-level preflight did not fail within 240 seconds")
    output = process.communicate(timeout=5)[0]
    result = subprocess.CompletedProcess(
        process.args,
        process.returncode,
        output,
        "",
    )
    assert port_samples
    assert not any(api or web for api, web in port_samples)
    assert not port_is_bound(8000)
    assert not port_is_bound(5173)
    return result, forbidden_processes


def assert_no_compose_residue(run_id: str) -> None:
    container_names = subprocess.run(
        [
            "docker",
            "ps",
            "--all",
            "--filter",
            f"name=itda_e2e_{run_id}",
            "--format",
            "{{.Names}}",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout
    volume_names = subprocess.run(
        [
            "docker",
            "volume",
            "ls",
            "--filter",
            f"name=itda_e2e_{run_id}",
            "--format",
            "{{.Name}}",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout
    assert container_names.strip() == ""
    assert volume_names.strip() == ""


def test_top_level_preflight_rejects_empty_browser_cache_without_side_effects(
    tmp_path: Path,
) -> None:
    browser_path = tmp_path / "empty-browser-cache"
    browser_path.mkdir()
    run_id = f"missing_browser_{os.getpid()}"

    result, forbidden_processes = run_failed_top_level_preflight(
        browser_path=browser_path,
        run_id=run_id,
    )

    assert result.returncode != 0
    assert "chromium revision 1228 executable" in result.stdout
    assert "playwright test" not in result.stdout
    assert forbidden_processes == []
    assert_no_compose_residue(run_id)


def test_top_level_preflight_rejects_missing_headless_shell_without_side_effects(
    tmp_path: Path,
) -> None:
    installed = installed_playwright_bundle()
    chromium_executable = installed["chromium"]
    headless_shell_executable = installed["chromium-headless-shell"]
    assert chromium_executable.is_file()
    assert headless_shell_executable.is_file()
    source_chromium = next(
        parent
        for parent in chromium_executable.parents
        if parent.name == f"chromium-{e2e_runtime.PLAYWRIGHT_CHROMIUM_REVISION}"
    )

    isolated_root = tmp_path / "partial-browser-cache"
    isolated_root.mkdir()
    (isolated_root / source_chromium.name).symlink_to(
        source_chromium,
        target_is_directory=True,
    )
    assert chromium_executable.is_file()
    source_headless_shell = next(
        parent
        for parent in headless_shell_executable.parents
        if parent.name.endswith(f"-{e2e_runtime.PLAYWRIGHT_CHROMIUM_REVISION}")
    )
    assert not (isolated_root / source_headless_shell.name).exists()
    run_id = f"missing_headless_{os.getpid()}"

    result, forbidden_processes = run_failed_top_level_preflight(
        browser_path=isolated_root,
        run_id=run_id,
    )

    assert result.returncode != 0
    assert "chromium-headless-shell revision 1228 executable" in result.stdout
    assert "playwright test" not in result.stdout
    assert forbidden_processes == []
    assert_no_compose_residue(run_id)
