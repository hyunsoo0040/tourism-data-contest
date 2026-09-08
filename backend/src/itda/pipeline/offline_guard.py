"""Fail-closed policy guard for opt-in live collection."""

from __future__ import annotations

import os

LIVE_COLLECTION_REFUSAL_EXIT_CODE = 78
_TRUTHY_VALUES = frozenset({"1", "true", "yes", "on"})


class LiveCollectionRefused(RuntimeError):
    """Raised before network I/O when live collection is not permitted."""

    exit_code = LIVE_COLLECTION_REFUSAL_EXIT_CODE

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"live collection refused: {reason}")


def _environment_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().casefold() in _TRUTHY_VALUES


def require_live_collection_allowed(*, explicit_opt_in: bool) -> None:
    """Reject disallowed live collection without performing any network operation."""

    if _environment_flag("CI"):
        raise LiveCollectionRefused("ci")
    if _environment_flag("ITDA_NO_NETWORK"):
        raise LiveCollectionRefused("no-network")
    if _environment_flag("ITDA_OFFLINE"):
        raise LiveCollectionRefused("offline")
    if not explicit_opt_in:
        raise LiveCollectionRefused("explicit-opt-in-required")
