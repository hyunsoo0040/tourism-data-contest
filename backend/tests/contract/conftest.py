"""Contract-test-wide provider boundary.

WR-B re-audit: the socket deny must be installed at COLLECTION TIME — before
any test module (and therefore any lane/helper import chain) executes — not
inside an autouse fixture that only arms per-test.  ``pytest_load_initial_conftests``
runs before pytest imports test modules, so the INET/DNS deny is already in
place when the first ``import itda...`` happens.

The deny is defense-in-depth beneath the OS-level
``sandbox-exec -p '(version 1)(allow default)(deny network*)'`` profile every
provider-relevant suite runs under; tests themselves construct ONLY explicit
``httpx.MockTransport`` local clients.
"""

from __future__ import annotations

import socket as _socket_module

_DENY_MARKER = "ITDA_CONTRACT_SUITE_INET_DENIED"

_ORIGINALS = {
    name: getattr(_socket_module, name)
    for name in ("create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex", "socket")
}


def _deny_create_connection(*args: object, **kwargs: object) -> object:
    raise OSError(97, "ITDA_CONTRACT_SUITE_CONNECT_DENIED")


def _deny_getaddrinfo(*args: object, **kwargs: object) -> list[object]:
    raise OSError(97, "ITDA_CONTRACT_SUITE_DNS_DENIED")


def _deny_gethostbyname(*args: object) -> str:
    raise OSError(97, "ITDA_CONTRACT_SUITE_DNS_DENIED")


def _deny_gethostbyname_ex(*args: object) -> tuple[str, list[str], list[str]]:
    raise OSError(97, "ITDA_CONTRACT_SUITE_DNS_DENIED")


_real_socket = _socket_module._socket.socket  # type: ignore[attr-defined]


def _family_aware_socket(*args: object, **kwargs: object) -> object:
    family = args[0] if args else kwargs.get("family", _socket_module.AF_INET)
    if family in (_socket_module.AF_INET, _socket_module.AF_INET6):
        raise OSError(97, _DENY_MARKER)
    return _real_socket(*args, **kwargs)  # type: ignore[arg-type]


def install_collection_time_network_deny() -> None:
    """Arm the process-wide INET/DNS deny exactly once (idempotent)."""

    if getattr(_socket_module, "_itda_contract_deny_installed", False):
        return
    replacements = {
        "create_connection": _deny_create_connection,
        "getaddrinfo": _deny_getaddrinfo,
        "gethostbyname": _deny_gethostbyname,
        "gethostbyname_ex": _deny_gethostbyname_ex,
        "socket": _family_aware_socket,
    }
    for name, replacement in replacements.items():
        setattr(_socket_module, name, replacement)
    _socket_module._itda_contract_deny_installed = True  # type: ignore[attr-defined]


# Install IMMEDIATELY at conftest import — conftest modules load before any
# collection/import of test modules.
install_collection_time_network_deny()


def pytest_load_initial_conftests(args):  # noqa: ANN001 - pytest hook signature
    """Pytest hook: fires before conftest/test-module imports; idempotent."""

    install_collection_time_network_deny()
