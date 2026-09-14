"""Production defaults preserve the public snapshot and the official collection stop."""

import importlib.util
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize(
    "path", ["deploy/swarm-stack.yaml", "deploy/portainer-stack.yaml", "docker-compose.yml"]
)
def test_deployments_do_not_restart_collection_and_pin_public_readiness(path):
    config = yaml.safe_load((ROOT / path).read_text())
    services = config["services"]
    backend = services["backend"]
    for key in (
        "ITDA_TOURISM_ENABLED",
        "ITDA_GROUNDED_RECOMMENDATIONS_ENABLED",
        "ITDA_OPERATING_INFORMATION_ENABLED",
    ):
        assert backend["environment"][key] == "${" + key + ":-0}"
    daily = services["daily-glm-refresh"]
    assert (
        daily["environment"]["ITDA_GROUNDED_DAILY_ENABLED"] == "${ITDA_GROUNDED_DAILY_ENABLED:-0}"
    )
    assert daily["deploy"]["replicas"] == "${ITDA_GROUNDED_DAILY_REPLICAS:-0}"
    for service in (backend, daily):
        assert (
            service["environment"]["ITDA_MODEL_SESSION_LIMIT"] == "${ITDA_MODEL_SESSION_LIMIT:-5}"
        )
    assert backend["environment"]["ITDA_AUTHENTICITY_ALLOW_DEVELOPMENT"] == "0"
    assert "itda.cli.authenticity_health" in backend["healthcheck"]["test"]
    migrate = services["migrate"]["environment"]
    assert migrate["ITDA_AUTHENTICITY_RELEASE_DIR"] == "/app/artifacts/authenticity/current"
    assert ":?" in migrate["ITDA_AUTHENTICITY_RELEASE_SHA256"]
    assert ":?" in migrate["ITDA_AUTHENTICITY_EXPECTED_PLACES"]
    assert not any(k.startswith("ITDA_GROUNDED_INITIAL_") for k in migrate)
    if path == "docker-compose.yml":
        assert (
            backend["environment"]["ITDA_AUTHENTICITY_DATABASE_URL"]
            == backend["environment"]["ITDA_DATABASE_URL"]
        )
        assert "app" in services["web"]["networks"]
    else:
        assert (
            'export ITDA_AUTHENTICITY_DATABASE_URL="$${ITDA_DATABASE_URL}"'
            in backend["command"][-1]
        )


def test_backend_image_includes_only_public_release_data():
    dockerfile = (ROOT / "backend/Dockerfile").read_text()
    ignore = (ROOT / ".dockerignore").read_text()
    assert "artifacts/national/current" not in dockerfile
    assert "artifacts/authenticity-v1/20260911/public-release/" in dockerfile
    assert "!artifacts/authenticity-v1/20260911/public-release/assessments/*.json" in ignore
    for private in ("!.secrets/", "!fixtures/", "!artifacts/authenticity-v1/20260911/full-2000/"):
        assert private not in ignore


def test_environment_generator_keeps_collection_stopped_and_pins_the_requested_release(monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "itda_test_generate_deploy_env", ROOT / "scripts/generate_deploy_env.py"
    )
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    monkeypatch.setattr(generator, "_password", lambda: "synthetic-password")
    monkeypatch.setattr(generator, "_session_key", lambda: "synthetic-session-key")
    rendered = generator._render(
        "example.invalid",
        "backend-test",
        "web-test",
        stack_name="test-stack",
        acme_email="test@example.invalid",
        dashboard_domain="dashboard.example.invalid",
        whoami_domain="whoami.example.invalid",
        dashboard_users_file=Path("/synthetic/dashboard-users"),
        authenticity_release_sha256="a" * 64,
        authenticity_places=1984,
    )
    values = dict(line.split("=", 1) for line in rendered.splitlines())
    for key in (
        "ITDA_TOURISM_ENABLED",
        "ITDA_GROUNDED_DAILY_ENABLED",
        "ITDA_GROUNDED_DAILY_REPLICAS",
    ):
        assert values[key] == "0"
    assert values["ITDA_MODEL_SESSION_LIMIT"] == "5"
    assert values["ITDA_AUTHENTICITY_RELEASE_SHA256"] == "a" * 64
    assert values["ITDA_AUTHENTICITY_EXPECTED_PLACES"] == "1984"
    assert values["ITDA_AUTHENTICITY_PREVIOUS_RELEASE_SHA256"] == "NONE"
