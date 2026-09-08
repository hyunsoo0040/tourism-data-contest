"""Wave 0 RED security boundaries for Phase 3 profile releases."""

from __future__ import annotations

import importlib
import importlib.util
import json
from dataclasses import dataclass, field
from types import ModuleType
from typing import Any

import pytest

CAPABILITY_MODULE = "itda.contracts.profile_release"


def _capability() -> ModuleType:
    try:
        available = importlib.util.find_spec(CAPABILITY_MODULE) is not None
    except ModuleNotFoundError:
        available = False
    if not available:
        pytest.fail("PHASE3-MISSING:profile-release-security", pytrace=False)
    return importlib.import_module(CAPABILITY_MODULE)


def _sensitive_markers() -> tuple[str, ...]:
    return (
        "synthetic-" + "peer-value-marker",
        "synthetic-" + "model-value-marker",
        "synthetic-" + "partition-marker",
        "synthetic-" + "identity-marker",
        "synthetic-" + "credential-marker",
    )


def _assert_redacted(channels: dict[str, object]) -> None:
    for channel, payload in channels.items():
        rendered = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
        if any(marker in rendered for marker in _sensitive_markers()):
            pytest.fail(f"PHASE3-LEAK:{channel}", pytrace=False)


@dataclass
class InMemoryTelemetryExporter:
    """Test-only exporter; never sends telemetry outside this process."""

    spans: list[dict[str, object]] = field(default_factory=list)

    def emit(self, **attributes: object) -> None:
        self.spans.append(dict(attributes))

    def export(self) -> tuple[dict[str, object], ...]:
        return tuple(self.spans)


@pytest.mark.parametrize("action", ["BUILD", "APPROVE", "ACTIVATE", "ROLLBACK"])
def test_authenticated_principal_is_the_only_role_authority(action: str) -> None:
    capability = _capability()

    with pytest.raises(ValueError, match="client|actor|principal"):
        capability.authorize_profile_release_action(
            action=action,
            authenticated_principal="synthetic-server-principal",
            builder_principal="synthetic-builder",
            client_actor_id="synthetic-forged-actor",
        )


@pytest.mark.parametrize("action", ["APPROVE", "ACTIVATE"])
def test_builder_cannot_approve_or_activate_its_own_release(action: str) -> None:
    capability = _capability()

    with pytest.raises(ValueError, match="builder|independent"):
        capability.authorize_profile_release_action(
            action=action,
            authenticated_principal="synthetic-builder",
            builder_principal="synthetic-builder",
            client_actor_id=None,
        )


def test_client_supplied_rollback_approver_is_rejected() -> None:
    capability = _capability()

    with pytest.raises(ValueError, match="client|approver|principal"):
        capability.validate_rollback_authority(
            authenticated_principal="synthetic-server-approver",
            builder_principal="synthetic-builder",
            client_approver_id="synthetic-forged-approver",
            reason="합성 장애 복구",
        )


@pytest.mark.parametrize(
    "reason",
    ["", "   ", "가" * 301],
    ids=("empty", "whitespace", "over-limit"),
)
def test_rollback_reason_is_trimmed_and_bounded(reason: str) -> None:
    capability = _capability()

    with pytest.raises(ValueError, match="reason"):
        capability.validate_rollback_authority(
            authenticated_principal="synthetic-server-approver",
            builder_principal="synthetic-builder",
            client_approver_id=None,
            reason=reason,
        )


def test_all_output_channels_are_membership_and_secret_free() -> None:
    capability = _capability()
    exporter = InMemoryTelemetryExporter()
    unsafe = {
        "release_sha256": "a" * 64,
        "status": "REFUSED",
        "input": _sensitive_markers()[0],
        "error": _sensitive_markers()[2],
        "credential": _sensitive_markers()[4],
    }

    safe = capability.redact_profile_release_channels(unsafe)
    exporter.emit(**safe["trace"])

    _assert_redacted(
        {
            "artifact": safe["artifact"],
            "stdout": safe["stdout"],
            "stderr": safe["stderr"],
            "error": safe["error"],
            "log": safe["log"],
            "trace": exporter.export(),
            "report": safe["report"],
        }
    )


def test_scanner_failure_never_echoes_the_matched_value() -> None:
    channels: dict[str, Any] = {"trace": {"value": _sensitive_markers()[0]}}

    with pytest.raises(pytest.fail.Exception) as failure:
        _assert_redacted(channels)

    assert str(failure.value) == "PHASE3-LEAK:trace"
