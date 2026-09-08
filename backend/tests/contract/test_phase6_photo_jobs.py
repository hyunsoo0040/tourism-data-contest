"""Controlled-RED contract for the Phase 6 photo job public lifecycle.

Wave 0 freezes the durable six-state vocabulary (queued, running,
succeeded, failed, expired, deleted), the complete legal transition
matrix, terminal immutability with idempotent same-terminal replay,
opaque SHA-256 job identity, profile ownership, and the hard wall
between internal dispatch/cleanup markers and the six public states.

Every assertion targets the absent ``itda.photo.contracts`` module, so
each test fails while naming the missing Phase 6 owner. The module is
provider-free: no provider client, credential, socket, or network
traffic is constructed, and provider environment variables are removed
for the whole module.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import ModuleType

import pytest

PUBLIC_STATES = frozenset(
    {"queued", "running", "succeeded", "failed", "expired", "deleted"}
)
TERMINAL_STATES = frozenset({"succeeded", "failed", "expired", "deleted"})
NON_TERMINAL_STATES = PUBLIC_STATES - TERMINAL_STATES
TERMINAL_CAUSES = frozenset(
    {
        "success",
        "rejection",
        "validation_failure",
        "provider_error",
        "timeout",
        "worker_crash",
        "explicit_deletion",
        "expiry",
        "orphan_cleanup",
    }
)
CAUSE_TERMINAL_STATES: Mapping[str, str] = {
    "success": "succeeded",
    "rejection": "failed",
    "validation_failure": "failed",
    "provider_error": "failed",
    "timeout": "failed",
    "worker_crash": "failed",
    "explicit_deletion": "deleted",
    "expiry": "expired",
    "orphan_cleanup": "deleted",
}
LEGAL_TRANSITIONS: Mapping[str, frozenset[str]] = {
    "queued": frozenset({"running", "failed", "expired", "deleted"}),
    "running": frozenset({"succeeded", "failed", "expired", "deleted"}),
    "succeeded": frozenset({"deleted"}),
    "failed": frozenset({"deleted"}),
    "expired": frozenset({"deleted"}),
    "deleted": frozenset(),
}
INTERNAL_DISPATCH_MARKERS = frozenset(
    {"reserved", "prepared", "client_constructed", "send_boundary"}
)
INTERNAL_CLEANUP_PHASES = frozenset(
    {"cleanup_pending", "cleanup_running", "cleanup_verified"}
)
FORBIDDEN_PUBLIC_FIELDS = (
    "filename",
    "original_filename",
    "image_bytes",
    "provider_payload",
    "provider_request",
    "provider_response",
    "trait",
    "traits",
    "score",
    "rank",
    "ranking",
    "recommendation",
    "confidence",
    "secret",
    "credential",
    "private_path",
)


@pytest.fixture(autouse=True)
def _no_provider_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("NVIDIA_KEY", "ZHIPUAI_API_KEY", "BIGMODEL_API_KEY", "OPENROUTER_API_KEY"):
        monkeypatch.delenv(name, raising=False)


def _photo_contracts() -> ModuleType:
    """Import the Phase 6 contracts module or name its absent owner."""

    try:
        from itda.photo import contracts
    except ModuleNotFoundError as error:
        pytest.fail(f"PHASE6-MISSING:photo-contracts-module ({error})", pytrace=False)
    return contracts


def test_public_state_vocabulary_is_exactly_six_with_no_aliases() -> None:
    contracts = _photo_contracts()
    states = contracts.PhotoJobPublicState

    assert {member.value for member in states} == PUBLIC_STATES
    assert len(states) == 6
    values = [member.value for member in states]
    assert len(set(values)) == len(values), "public state aliases are forbidden"
    assert contracts.PHOTO_JOB_PUBLIC_STATES == PUBLIC_STATES


def test_persisted_status_union_equals_public_union_and_never_seventh_state() -> None:
    contracts = _photo_contracts()
    status = contracts.PhotoJobStatus
    public = contracts.PhotoJobPublicState

    assert status is not public, "persisted status must be its own vocabulary type"
    assert {member.value for member in status} == PUBLIC_STATES
    assert len(status) == 6
    assert "cleanup_pending" not in {member.value for member in status}
    assert "cleanup_pending" not in {member.value for member in public}
    assert contracts.PHOTO_JOB_INTERNAL_CLEANUP_PHASES == INTERNAL_CLEANUP_PHASES


def test_internal_dispatch_and_cleanup_markers_are_disjoint_from_public_states() -> None:
    contracts = _photo_contracts()

    assert contracts.PHOTO_JOB_INTERNAL_DISPATCH_MARKERS == INTERNAL_DISPATCH_MARKERS
    assert contracts.PHOTO_JOB_INTERNAL_DISPATCH_MARKERS.isdisjoint(PUBLIC_STATES)
    assert contracts.PHOTO_JOB_INTERNAL_CLEANUP_PHASES.isdisjoint(PUBLIC_STATES)
    assert frozenset() == INTERNAL_DISPATCH_MARKERS & INTERNAL_CLEANUP_PHASES


def test_internal_marker_values_decode_fail_as_public_state() -> None:
    contracts = _photo_contracts()
    public = contracts.PhotoJobPublicState

    for hostile in INTERNAL_DISPATCH_MARKERS | INTERNAL_CLEANUP_PHASES:
        with pytest.raises(ValueError):
            public(hostile)


def test_legal_transition_matrix_is_exact_and_total() -> None:
    contracts = _photo_contracts()

    assert set(contracts.PHOTO_JOB_LEGAL_TRANSITIONS) == PUBLIC_STATES
    for source, targets in contracts.PHOTO_JOB_LEGAL_TRANSITIONS.items():
        assert set(targets) <= PUBLIC_STATES
        assert set(targets) == LEGAL_TRANSITIONS[source], (source, set(targets))


def test_transition_validator_accepts_only_legal_pairs() -> None:
    contracts = _photo_contracts()

    for source in sorted(PUBLIC_STATES):
        for target in sorted(PUBLIC_STATES):
            legal = target in LEGAL_TRANSITIONS[source]
            assert contracts.is_legal_transition(source, target) is legal, (source, target)
            if legal:
                contracts.validate_transition(source, target)
            else:
                with pytest.raises(contracts.PhotoJobTransitionError):
                    contracts.validate_transition(source, target)
    assert contracts.is_terminal("succeeded")
    assert contracts.is_terminal("failed")
    assert contracts.is_terminal("expired")
    assert contracts.is_terminal("deleted")
    assert not contracts.is_terminal("queued")
    assert not contracts.is_terminal("running")


def test_terminal_self_replay_is_idempotent_and_nonterminal_self_loop_rejected() -> None:
    contracts = _photo_contracts()
    job_id = "a" * 64

    for terminal in sorted(TERMINAL_STATES):
        cause = next(
            cause for cause, state in CAUSE_TERMINAL_STATES.items() if state == terminal
        )
        replayed = contracts.PhotoJobStateTransition(
            job_id=job_id,
            from_state=terminal,
            to_state=terminal,
            cause=cause,
            transitioned_at="2026-08-28T00:00:00Z",
        )
        assert replayed.to_state == terminal
        conflicting_cause = next(
            test_cause
            for test_cause, test_state in CAUSE_TERMINAL_STATES.items()
            if test_state != terminal
        )
        with pytest.raises((ValueError, contracts.PhotoJobTransitionError)):
            contracts.PhotoJobStateTransition(
                job_id=job_id,
                from_state=terminal,
                to_state=terminal,
                cause=conflicting_cause,
                transitioned_at="2026-08-28T00:00:00Z",
            )
    for non_terminal in sorted(NON_TERMINAL_STATES):
        with pytest.raises((ValueError, contracts.PhotoJobTransitionError)):
            contracts.PhotoJobStateTransition(
                job_id=job_id,
                from_state=non_terminal,
                to_state=non_terminal,
                cause="success" if non_terminal == "queued" else "worker_crash",
                transitioned_at="2026-08-28T00:00:00Z",
            )


def test_terminal_outcome_cannot_be_rewritten_to_another_terminal_outcome() -> None:
    contracts = _photo_contracts()
    job_id = "a" * 64

    for source in sorted(TERMINAL_STATES - {"deleted"}):
        for target in sorted(TERMINAL_STATES - {source}):
            with pytest.raises(contracts.PhotoJobTransitionError):
                contracts.PhotoJobStateTransition(
                    job_id=job_id,
                    from_state=source,
                    to_state=target,
                    cause="explicit_deletion" if target == "deleted" else "success",
                    transitioned_at="2026-08-28T00:00:00Z",
                )


def test_terminal_cause_codes_are_exactly_nine_and_map_to_terminal_states() -> None:
    contracts = _photo_contracts()
    causes = contracts.PhotoTerminalCause

    assert {member.value for member in causes} == TERMINAL_CAUSES
    assert len(causes) == 9
    assert contracts.PHOTO_JOB_TERMINAL_CAUSES == TERMINAL_CAUSES
    assert dict(contracts.PHOTO_JOB_CAUSE_TERMINAL_STATES) == dict(CAUSE_TERMINAL_STATES)


def test_job_identity_is_opaque_sha256_only() -> None:
    contracts = _photo_contracts()

    assert contracts.PHOTO_JOB_ID_PATTERN == "^[0-9a-f]{64}$"
    ref = contracts.PhotoJobRef(
        job_id="b" * 64,
        profile_id="owner-profile-1",
        state="queued",
    )
    assert ref.job_id == "b" * 64
    for hostile_job_id in (
        "B" * 64,
        "b" * 63,
        "b" * 65,
        "g" * 64,
        "../" + "b" * 64,
        "b" * 64 + "/../secret",
        "",
        "job-1",
        "b" * 64 + "\x00",
    ):
        with pytest.raises(ValueError):
            contracts.PhotoJobRef(job_id=hostile_job_id, profile_id="p", state="queued")


def test_job_ref_binds_exactly_one_profile_owner() -> None:
    contracts = _photo_contracts()

    assert set(contracts.PhotoJobRef.model_fields) == {"job_id", "profile_id", "state"}
    for missing_profile in ({"job_id": "b" * 64, "state": "queued"},):
        with pytest.raises(ValueError):
            contracts.PhotoJobRef.model_validate(missing_profile)
    for hostile_profile in ("", "   ", None):
        payload = {"job_id": "b" * 64, "state": "queued"}
        if hostile_profile is not None:
            payload["profile_id"] = hostile_profile
        with pytest.raises(ValueError):
            contracts.PhotoJobRef.model_validate(payload)


def test_public_contracts_carry_no_provider_filename_or_authority_fields() -> None:
    contracts = _photo_contracts()

    fields = set(contracts.PhotoJobRef.model_fields)
    for forbidden in FORBIDDEN_PUBLIC_FIELDS:
        assert forbidden not in fields
    assert contracts.PhotoJobRef.model_config.get("extra") == "forbid"
    detail_fields = set(contracts.PhotoJobErrorDetail.model_fields)
    assert detail_fields == {"code", "message_ko"}
    for forbidden in FORBIDDEN_PUBLIC_FIELDS:
        assert forbidden not in detail_fields


def test_decode_rejects_unknown_malformed_without_echoing_internals() -> None:
    contracts = _photo_contracts()
    valid = contracts.decode_photo_job_ref(
        {"job_id": "c" * 64, "profile_id": "owner-profile-1", "state": "queued"}
    )
    assert valid.state.value == "queued"

    hostile_payloads = (
        {"job_id": "c" * 64, "profile_id": "p", "state": "cleanup_pending"},
        {"job_id": "c" * 64, "profile_id": "p", "state": "send_boundary"},
        {"job_id": "c" * 64, "profile_id": "p", "state": "totally-unknown"},
        {"job_id": "c" * 64, "profile_id": "p", "state": ""},
        {"job_id": "not-hex", "profile_id": "p", "state": "queued"},
        {"profile_id": "p", "state": "queued"},
        {"job_id": "c" * 64, "state": "queued"},
        "not-a-mapping",
        None,
        {"job_id": "c" * 64, "profile_id": "p", "state": "queued", "score": 99},
    )
    internal_tokens = INTERNAL_DISPATCH_MARKERS | INTERNAL_CLEANUP_PHASES
    for hostile in hostile_payloads:
        with pytest.raises(contracts.PhotoJobDecodeError) as captured:
            contracts.decode_photo_job_ref(hostile)
        error_text = f"{captured.value}"
        for token in internal_tokens:
            assert token not in error_text, (hostile, token)
        detail = captured.value.detail
        assert detail.code in set(contracts.PhotoJobErrorCode)
        assert detail.message_ko
        assert detail.code.value in {"PHOTO_JOB_DECODE_FAILED", "PHOTO_JOB_TRANSITION_ILLEGAL"}
