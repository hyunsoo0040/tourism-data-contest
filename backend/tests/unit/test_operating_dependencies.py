from __future__ import annotations

from pathlib import Path

import pytest

import itda.api.dependencies as dependencies
from itda.pipeline.offline_guard import LiveCollectionRefused


def _clear_policy_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "CI",
        "ITDA_NO_NETWORK",
        "ITDA_OFFLINE",
        "ITDA_OPERATING_INFORMATION_ENABLED",
        "ITDA_TOUR_API_SERVICE_KEY_FILE",
        "TOUR_API_SERVICE_KEY",
    ):
        monkeypatch.delenv(key, raising=False)


def test_disabled_operating_information_never_resolves_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_policy_environment(monkeypatch)

    def forbidden_read(*args: object, **kwargs: object) -> str:
        raise AssertionError("disabled enrichment must not read credentials")

    monkeypatch.setattr(Path, "read_text", forbidden_read)
    monkeypatch.setattr(
        dependencies,
        "TourApiOperatingProvider",
        lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("disabled enrichment must not construct a provider")
        ),
    )

    assert dependencies._operating_information_service() is None


def test_offline_policy_refuses_before_credentials_or_provider_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_policy_environment(monkeypatch)
    monkeypatch.setenv("ITDA_OPERATING_INFORMATION_ENABLED", "1")
    monkeypatch.setenv("ITDA_OFFLINE", "1")
    monkeypatch.setenv("ITDA_TOUR_API_SERVICE_KEY_FILE", "/forbidden/credential")

    def forbidden_read(*args: object, **kwargs: object) -> str:
        raise AssertionError("offline refusal must precede credential access")

    monkeypatch.setattr(Path, "read_text", forbidden_read)
    monkeypatch.setattr(
        dependencies,
        "TourApiOperatingProvider",
        lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("offline refusal must precede provider construction")
        ),
    )

    with pytest.raises(LiveCollectionRefused, match="offline"):
        dependencies._operating_information_service()


def test_enabled_operating_information_rejects_invalid_numeric_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_policy_environment(monkeypatch)
    monkeypatch.setenv("ITDA_OPERATING_INFORMATION_ENABLED", "1")
    monkeypatch.setenv("TOUR_API_SERVICE_KEY", "synthetic-test-credential")
    monkeypatch.setenv("ITDA_OPERATING_INFORMATION_TIMEOUT_SECONDS", "not-a-number")

    with pytest.raises(ValueError, match="could not convert string to float"):
        dependencies._operating_information_service()
