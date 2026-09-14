"""Old stack DSNs stay usable; deployment failures never print secret payloads."""

import json
from types import SimpleNamespace

import psycopg
import pytest
from fastapi import HTTPException
from sqlalchemy.exc import ProgrammingError

from itda.api.routes import authenticity
from itda.cli import deploy_database


@pytest.mark.parametrize("override", [None, "explicit-runtime-dsn"])
def test_existing_stack_runtime_dsn_and_explicit_override(monkeypatch, override):
    monkeypatch.setenv("ITDA_DATABASE_URL", "existing-runtime-dsn")
    if override is None:
        monkeypatch.delenv("ITDA_AUTHENTICITY_DATABASE_URL", raising=False)
    else:
        monkeypatch.setenv("ITDA_AUTHENTICITY_DATABASE_URL", override)
    seen = []
    monkeypatch.setattr(authenticity, "create_database_engine", lambda dsn: seen.append(dsn))
    monkeypatch.setattr(authenticity, "Repository", lambda engine: object())
    monkeypatch.setattr(authenticity, "Service", lambda repository, **kwargs: object())
    authenticity.get_service.cache_clear()
    try:
        authenticity.get_service()
        assert seen == [override or "existing-runtime-dsn"]
    finally:
        authenticity.get_service.cache_clear()


def test_explicit_empty_dsn_does_not_silently_switch_databases(monkeypatch):
    monkeypatch.setenv("ITDA_DATABASE_URL", "existing-runtime-dsn")
    monkeypatch.setenv("ITDA_AUTHENTICITY_DATABASE_URL", "")
    authenticity.get_service.cache_clear()
    try:
        with pytest.raises(HTTPException) as error:
            authenticity.get_service()
        assert error.value.status_code == 503
    finally:
        authenticity.get_service.cache_clear()


@pytest.mark.parametrize("failed_stage", ["roles", "schema", "public_release"])
def test_failure_identifies_stage_without_dsn_or_exception_payload(
    monkeypatch, capsys, failed_stage
):
    secret = "private-password-and-sql-canary"
    monkeypatch.setenv("ITDA_AUTHENTICITY_RELEASE_DIR", "/synthetic/release")
    monkeypatch.setattr(deploy_database, "load_settings", lambda: SimpleNamespace(admin_dsn=secret))

    def step(stage):
        def invoke(*args, **kwargs):
            if stage == failed_stage:
                raise RuntimeError(secret)
            return {"state": "retained", "places": 1984, "release_sha256": "a" * 64}

        return invoke

    monkeypatch.setattr(deploy_database, "provision_roles", step("roles"))
    monkeypatch.setattr(deploy_database, "upgrade_schema", step("schema"))
    monkeypatch.setattr(
        deploy_database, "ensure_initial_authenticity_release", step("public_release")
    )
    assert deploy_database.main() == 1
    output = capsys.readouterr().out
    assert secret not in output
    event = json.loads(output.splitlines()[-1])
    assert event["stage"] == failed_stage
    assert event["code"] == "DEPLOYMENT_STAGE_FAILED"


def test_sqlstate_is_reported_without_sql_or_parameters():
    secret = "private-sql-and-parameter-canary"
    original = psycopg.errors.InsufficientPrivilege(secret)
    error = ProgrammingError(secret, {"password": secret}, original)
    event = deploy_database.deployment_failure(error, "schema")
    assert event["sqlstate"] == "42501"
    assert secret not in json.dumps(event)


def test_missing_configuration_names_the_variable_without_its_value(monkeypatch, capsys):
    monkeypatch.delenv("ITDA_RUNTIME_ROLE", raising=False)
    assert deploy_database.main() == 1
    event = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert event["stage"] == "configuration"
    assert event["variable"] == "ITDA_RUNTIME_ROLE"
    assert event["code"] == "DEPLOYMENT_CONFIGURATION_INVALID"


@pytest.mark.parametrize(
    "code", ["AUTHENTICITY_PUBLIC_DEPLOYMENT_PIN_MISMATCH", "ACTIVE_RELEASE_CHANGED"]
)
def test_public_pin_or_active_pointer_conflicts_remain_explainable(code):
    assert deploy_database.deployment_failure(ValueError(code), "public_release")["code"] == code
