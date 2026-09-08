"""Security-test-wide provider boundary.

WR-B final round: the INET/DNS socket deny must be installed at COLLECTION
TIME — before any test module (and therefore any lane/helper import chain)
executes — mirroring backend/tests/contract/conftest.py.  This is
defense-in-depth beneath the OS-level
``sandbox-exec -p '(version 1)(allow default)(deny network*)'`` profile;
tests construct ONLY explicit ``httpx.MockTransport`` local clients.
"""

from __future__ import annotations

import socket as _socket_module

_DENY_MARKER = "ITDA_SECURITY_SUITE_INET_DENIED"


def _deny_create_connection(*args: object, **kwargs: object) -> object:
    raise OSError(97, "ITDA_SECURITY_SUITE_CONNECT_DENIED")


def _deny_getaddrinfo(*args: object, **kwargs: object) -> list[object]:
    raise OSError(97, "ITDA_SECURITY_SUITE_DNS_DENIED")


def _deny_gethostbyname(*args: object) -> str:
    raise OSError(97, "ITDA_SECURITY_SUITE_DNS_DENIED")


def _deny_gethostbyname_ex(*args: object) -> tuple[str, list[str], list[str]]:
    raise OSError(97, "ITDA_SECURITY_SUITE_DNS_DENIED")


_real_socket = _socket_module._socket.socket  # type: ignore[attr-defined]


def _family_aware_socket(*args: object, **kwargs: object) -> object:
    family = args[0] if args else kwargs.get("family", _socket_module.AF_INET)
    if family in (_socket_module.AF_INET, _socket_module.AF_INET6):
        raise OSError(97, _DENY_MARKER)
    return _real_socket(*args, **kwargs)  # type: ignore[arg-type]


def install_collection_time_network_deny() -> None:
    """Arm the process-wide INET/DNS deny exactly once (idempotent)."""

    if getattr(_socket_module, "_itda_security_deny_installed", False):
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
    _socket_module._itda_security_deny_installed = True  # type: ignore[attr-defined]


# Install IMMEDIATELY at conftest import — before any test module loads.
install_collection_time_network_deny()


def pytest_load_initial_conftests(args):  # noqa: ANN001 - pytest hook signature
    """Pytest hook: fires before conftest/test-module imports; idempotent."""

    install_collection_time_network_deny()
