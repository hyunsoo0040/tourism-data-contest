"""Production scheduling never falls back to a historical raw-only batch."""

from __future__ import annotations

import sys

import pytest

from itda.cli import run_daily_glm_refresh as cli
from itda.pipeline.offline_guard import LiveCollectionRefused


@pytest.fixture(autouse=True)
def reject_legacy_scheduler(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("production entrypoint reached a historical raw-only scheduler")

    for name in ("_validate_authority", "_load_artifacts", "_run_one", "_run_recollection_command"):
        monkeypatch.setattr(cli, name, forbidden)


@pytest.mark.parametrize("value", [None, "", "  ", "1", "true", "YES", "on"])
def test_default_and_enabled_entrypoint_run_grounded_scheduler(monkeypatch, value):
    if value is None:
        monkeypatch.delenv("ITDA_GROUNDED_DAILY_ENABLED", raising=False)
    else:
        monkeypatch.setenv("ITDA_GROUNDED_DAILY_ENABLED", value)
    # Legacy activation authority is neither required nor used for grounded pairs.
    monkeypatch.delenv("ITDA_DAILY_GLM_REFRESH_AUTHORITY_SHA256", raising=False)

    def grounded():
        raise SystemExit(0)

    monkeypatch.setattr(cli, "_run_grounded_scheduler", grounded)
    with pytest.raises(SystemExit) as outcome:
        cli.main()
    assert outcome.value.code == 0


@pytest.mark.parametrize("value", ["0", "false", "NO", " off "])
def test_explicit_disable_stops_before_any_scheduler(monkeypatch, value):
    monkeypatch.setenv("ITDA_GROUNDED_DAILY_ENABLED", value)
    monkeypatch.setattr(cli, "_run_grounded_scheduler", lambda: pytest.fail("disabled batch ran"))
    with pytest.raises(RuntimeError, match="disabled; no daily batch will run"):
        cli.main()


def test_invalid_switch_does_not_start_either_scheduler(monkeypatch):
    monkeypatch.setenv("ITDA_GROUNDED_DAILY_ENABLED", "legacy")
    monkeypatch.setattr(cli, "_run_grounded_scheduler", lambda: pytest.fail("invalid batch ran"))
    with pytest.raises(RuntimeError, match="configuration rejected"):
        cli.main()


@pytest.mark.parametrize("guard", ["CI", "ITDA_NO_NETWORK", "ITDA_OFFLINE"])
def test_default_entrypoint_still_obeys_offline_guards_before_credentials_or_database(
    monkeypatch, guard
):
    monkeypatch.delenv("ITDA_GROUNDED_DAILY_ENABLED", raising=False)
    monkeypatch.setenv(guard, "1")
    monkeypatch.setattr(sys, "argv", ["run_daily_glm_refresh", "--once"])
    monkeypatch.setattr(cli, "_secret", lambda *args: pytest.fail("credentials read offline"))
    monkeypatch.setattr(
        cli, "create_database_engine", lambda *args: pytest.fail("database touched before guard")
    )
    with pytest.raises(LiveCollectionRefused):
        cli.main()
