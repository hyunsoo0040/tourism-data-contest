from __future__ import annotations

import socket

import pytest

from itda.pipeline.offline_guard import (
    LIVE_COLLECTION_REFUSAL_EXIT_CODE,
    LiveCollectionRefused,
    require_live_collection_allowed,
)


@pytest.mark.parametrize(
    ("environment", "explicit_opt_in", "expected_reason"),
    [
        ({"CI": "true"}, True, "ci"),
        ({}, False, "explicit-opt-in-required"),
        ({"ITDA_NO_NETWORK": "1"}, True, "no-network"),
        ({"ITDA_OFFLINE": "yes"}, True, "offline"),
    ],
)
def test_live_collection_is_refused_before_any_socket_call(
    monkeypatch: pytest.MonkeyPatch,
    environment: dict[str, str],
    explicit_opt_in: bool,
    expected_reason: str,
) -> None:
    for key in ("CI", "ITDA_NO_NETWORK", "ITDA_OFFLINE"):
        monkeypatch.delenv(key, raising=False)
    for key, value in environment.items():
        monkeypatch.setenv(key, value)

    socket_calls = 0

    def forbidden_socket(*args: object, **kwargs: object) -> None:
        nonlocal socket_calls
        socket_calls += 1
        raise AssertionError("offline refusal must happen before socket creation")

    monkeypatch.setattr(socket, "socket", forbidden_socket)

    with pytest.raises(LiveCollectionRefused) as caught:
        require_live_collection_allowed(explicit_opt_in=explicit_opt_in)

    assert caught.value.reason == expected_reason
    assert caught.value.exit_code == LIVE_COLLECTION_REFUSAL_EXIT_CODE == 78
    assert str(caught.value) == f"live collection refused: {expected_reason}"
    assert socket_calls == 0


def test_explicit_local_opt_in_is_allowed_without_touching_the_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key in ("CI", "ITDA_NO_NETWORK", "ITDA_OFFLINE"):
        monkeypatch.delenv(key, raising=False)

    socket_calls = 0

    def forbidden_socket(*args: object, **kwargs: object) -> None:
        nonlocal socket_calls
        socket_calls += 1
        raise AssertionError("the guard validates policy; it never opens a socket")

    monkeypatch.setattr(socket, "socket", forbidden_socket)

    require_live_collection_allowed(explicit_opt_in=True)

    assert socket_calls == 0
