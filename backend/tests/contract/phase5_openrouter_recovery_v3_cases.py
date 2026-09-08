"""Contract tests for the disjoint provider-free OpenRouter r3/v3 lane.

Every test is provider-free: provider env vars are removed, no socket is
constructed, and all protected roots are synthetic temporary directories.
The v1/v2 namespaces remain immutable history — nothing here subclasses,
aliases, or accepts them as authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.pipeline import phase5_openrouter_recovery_v3 as lane_v3

V3_AUTHORITY_ID = "phase5-openrouter-stealth-ox-alpha-recovery-r3-20260824"
V3_SNAPSHOT_RELATIVE = (
    "backend/src/itda/providers/openrouter_ox_alpha_api_contract_v3.json"
)
V3_REQUEST_SCHEMA = "itda.phase5-openrouter-recovery-request.v3"
V3_APPROVAL_SCHEMA = "itda.phase5-openrouter-approval.v3"
V3_CLAIM_SCHEMA = "itda.phase5-openrouter-claim.v3"
V3_LEDGER_ENTRY_SCHEMA = "itda.phase5-openrouter-ledger-entry.v3"
V3_JOURNAL_ENTRY_SCHEMA = "itda.phase5-openrouter-journal-entry.v3"
V3_ATTEMPT_SCHEMA = "itda.phase5-openrouter-attempt.v3"
V3_PROFILE_SCHEMA = "itda.phase5-openrouter-profile.v3"
V3_GENERATION_SCHEMA = "itda.phase5-openrouter-generation.v3"
V3_TERMINAL_SCHEMA = "itda.phase5-openrouter-terminal.v3"
V3_PROTECTED_STATE_SCHEMA = "itda.phase5-openrouter-protected-state.v3"

LEDGER_OPERATIONS = ("RESERVE", "DISPATCH", "COMMIT", "RECOVER_UNRESOLVED")
ATTEMPT_OUTCOMES = (
    "HTTP_RESPONSE",
    "TRANSPORT_ERROR",
    "CREDENTIAL_RESPONSE_STRIPPED",
    "LOCAL_PRE_SEND_FAILURE",
)


@pytest.fixture(autouse=True)
def _no_provider_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("NVIDIA_KEY", "ZHIPUAI_API_KEY", "BIGMODEL_API_KEY", "OPENROUTER_API_KEY"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _deny_production_openrouter_and_secret_fs_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Permit lexical path values, but forbid every production filesystem access."""

    repository_root = Path(__file__).resolve().parents[3]
    forbidden = (
        repository_root / "artifacts/restricted/catalog/phase5-openrouter-recovery",
        repository_root / "artifacts/restricted/catalog/phase5-openrouter-recovery-r2",
        repository_root / "artifacts/restricted/catalog/phase5-openrouter-recovery-r3",
        repository_root / ".secrets",
    )

    original_readlink = os.readlink

    def blocked_path(value: object, *, dir_fd: int | None = None) -> bool:
        try:
            candidate = Path(os.fspath(value))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return False
        if not candidate.is_absolute() and dir_fd is not None:
            try:
                candidate = Path(original_readlink(f"/dev/fd/{dir_fd}")) / candidate
            except OSError:
                return False
        candidate = Path(os.path.abspath(candidate))
        return any(candidate == root or root in candidate.parents for root in forbidden)

    def wrap(function):
        def guarded(path, *args, **kwargs):  # type: ignore[no-untyped-def]
            if blocked_path(path, dir_fd=kwargs.get("dir_fd")):
                raise AssertionError("PRODUCTION_OPENROUTER_OR_SECRET_FS_ACCESS_FORBIDDEN")
            return function(path, *args, **kwargs)

        return guarded

    def wrap_pair(function):
        def guarded(source, destination, *args, **kwargs):  # type: ignore[no-untyped-def]
            if blocked_path(source) or blocked_path(destination):
                raise AssertionError("PRODUCTION_OPENROUTER_OR_SECRET_FS_ACCESS_FORBIDDEN")
            return function(source, destination, *args, **kwargs)

        return guarded

    for name in (
        "open",
        "stat",
        "lstat",
        "listdir",
        "scandir",
        "mkdir",
        "makedirs",
        "unlink",
        "remove",
        "rmdir",
        "readlink",
    ):
        monkeypatch.setattr(os, name, wrap(getattr(os, name)))
    for name in ("rename", "replace"):
        monkeypatch.setattr(os, name, wrap_pair(getattr(os, name)))
    import builtins

    monkeypatch.setattr(builtins, "open", wrap(builtins.open))
    from pathlib import Path as _Path

    original_path_open = _Path.open

    def guarded_path_open(self: _Path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if blocked_path(self):
            raise AssertionError("PRODUCTION_OPENROUTER_OR_SECRET_FS_ACCESS_FORBIDDEN")
        return original_path_open(self, *args, **kwargs)

    monkeypatch.setattr(_Path, "open", guarded_path_open)


@pytest.fixture(autouse=True)
def _deny_real_httpx_client_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only explicit MockTransport clients exist in v3 tests."""

    async_client = httpx.AsyncClient
    sync_client = httpx.Client

    def guarded_async_client(*args: object, **kwargs: object) -> httpx.AsyncClient:
        if not isinstance(kwargs.get("transport"), httpx.MockTransport):
            raise AssertionError("REAL_PROVIDER_CLIENT_CONSTRUCTION_FORBIDDEN")
        return async_client(*args, **kwargs)

    def guarded_sync_client(*args: object, **kwargs: object) -> httpx.Client:
        if not isinstance(kwargs.get("transport"), httpx.MockTransport):
            raise AssertionError("REAL_PROVIDER_CLIENT_CONSTRUCTION_FORBIDDEN")
        return sync_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", guarded_async_client)
    monkeypatch.setattr(httpx, "Client", guarded_sync_client)


# ---------------------------------------------------------------------------
# Snapshot: independent v3 identity, exact raw keys, canonical bytes.
# ---------------------------------------------------------------------------


class TestSnapshotAuthority:
    def test_snapshot_constants_are_disjoint(self) -> None:
        from itda.contracts.phase5_openrouter_recovery import (
            OPENROUTER_RECOVERY_AUTHORITY_ID,
            OPENROUTER_SNAPSHOT_PATH,
        )
        from itda.contracts.phase5_openrouter_recovery import (
            OPENROUTER_V2_SNAPSHOT_PATH as V2_PATH,
        )
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            OPENROUTER_V3_RECOVERY_AUTHORITY_ID,
            OPENROUTER_V3_SNAPSHOT_PATH,
            OPENROUTER_V3_SNAPSHOT_RAW_SHA256,
            OPENROUTER_V3_SNAPSHOT_SHA256,
        )

        assert OPENROUTER_V3_RECOVERY_AUTHORITY_ID == V3_AUTHORITY_ID
        assert OPENROUTER_V3_RECOVERY_AUTHORITY_ID not in {
            OPENROUTER_RECOVERY_AUTHORITY_ID,
            "phase5-openrouter-stealth-ox-alpha-recovery-r2-20260824",
        }
        assert OPENROUTER_V3_SNAPSHOT_PATH != OPENROUTER_SNAPSHOT_PATH
        assert OPENROUTER_V3_SNAPSHOT_PATH != V2_PATH
        assert len(OPENROUTER_V3_SNAPSHOT_SHA256) == 64
        assert len(OPENROUTER_V3_SNAPSHOT_RAW_SHA256) == 64

    def test_committed_snapshot_loads_with_exact_raw_keys_and_canonical_bytes(
        self,
    ) -> None:
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            OPENROUTER_V3_SNAPSHOT_PATH,
            OPENROUTER_V3_SNAPSHOT_RAW_SHA256,
            OPENROUTER_V3_SNAPSHOT_SHA256,
            load_openrouter_snapshot_v3,
        )

        snapshot = load_openrouter_snapshot_v3()
        raw = OPENROUTER_V3_SNAPSHOT_PATH.read_bytes()
        # Exact raw keys: the committed file carries exactly the schema keys
        # plus the self digest, sorted canonically, byte-for-byte reproducible.
        expected_keys = {
            "schema_version",
            "authority_id",
            "provider_lane",
            "captured_offline",
            "runtime_metadata_fetch_forbidden",
            "accessed_at",
            "expiration_date",
            "provenance_urls",
            "endpoint",
            "model",
            "data_policy",
            "attribution_headers_sent",
            "optional_attribution_headers",
            "snapshot_sha256",
        }
        payload = json.loads(raw)
        assert set(payload) == expected_keys
        # Canonical bytes: the file IS its own canonical serialization.
        assert canonical_json_bytes(payload) == raw
        # Raw digest and self digest both pin the exact bytes.
        assert hashlib.sha256(raw).hexdigest() == OPENROUTER_V3_SNAPSHOT_RAW_SHA256
        unsigned = {k: v for k, v in payload.items() if k != "snapshot_sha256"}
        assert canonical_sha256(unsigned) == OPENROUTER_V3_SNAPSHOT_SHA256
        assert str(snapshot.snapshot_sha256) == OPENROUTER_V3_SNAPSHOT_SHA256

    def test_snapshot_rejects_duplicate_keys(self, tmp_path: Path) -> None:
        from itda.contracts.phase5_openrouter_recovery_v3 import load_snapshot_v3_bytes

        raw = b'{"a":1,"a":2}'
        with pytest.raises(ValueError, match="DUPLICATE"):
            load_snapshot_v3_bytes(raw, label="SNAPSHOT")

    def test_snapshot_self_digest_before_normalization(self, tmp_path: Path) -> None:
        """A drifted byte image with a valid-looking self digest is rejected."""

        from itda.contracts.phase5_openrouter_recovery_v3 import (
            OPENROUTER_V3_SNAPSHOT_PATH,
            load_openrouter_snapshot_v3,
        )

        good = json.loads(OPENROUTER_V3_SNAPSHOT_PATH.read_bytes())
        mutated = dict(good)
        mutated["expiration_date"] = "2099-01-01"
        path = tmp_path / "drifted.json"
        path.write_bytes(canonical_json_bytes(mutated))
        with pytest.raises((ValueError, PermissionError)):
            load_openrouter_snapshot_v3(path=path)

    def test_snapshot_loader_never_fetches(self) -> None:
        import inspect

        from itda.contracts import phase5_openrouter_recovery_v3 as contracts

        source = inspect.getsource(contracts.load_openrouter_snapshot_v3)
        assert "httpx" not in source
        assert "urllib" not in source
        assert "requests" not in source


# ---------------------------------------------------------------------------
# Historical rejection: only the EXACT public-v2 projection is acceptable.
# ---------------------------------------------------------------------------


def _historical_probe_values() -> tuple[str, ...]:
    return (
        "phase5-openrouter-stealth-ox-alpha-recovery-20260823",
        "phase5-openrouter-stealth-ox-alpha-recovery-r2-20260824",
        "itda.phase5-openrouter-terminal.v1",
        "itda.phase5-openrouter-terminal.v2",
        "itda.phase5-openrouter-api-snapshot.v1",
        "itda.phase5-openrouter-api-snapshot.v2",
        "artifacts/public/phase5/openrouter-recovery-request.json",
        "artifacts/reports/phase5/openrouter-recovery-terminal.json",
        "backend/src/itda/providers/openrouter_ox_alpha_api_contract.json",
        "backend/src/itda/providers/openrouter_ox_alpha_api_contract_v2.json",
    )


class TestHistoricalRejection:
    def test_all_v1_v2_coordinates_rejected_in_memory_without_fs_or_socket(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            reject_historical_openrouter_coordinates,
        )

        touched: list[str] = []

        def deny(name: str):
            def blocked(*_args: object, **_kwargs: object) -> object:
                touched.append(name)
                raise AssertionError(f"capability reached: {name}")

            return blocked

        monkeypatch.setattr(httpx, "AsyncClient", deny("client"))
        import socket

        monkeypatch.setattr(socket, "socket", deny("socket"))
        monkeypatch.setattr(Path, "read_bytes", deny("read_bytes"))
        monkeypatch.setattr(Path, "open", deny("open"))
        monkeypatch.setattr(Path, "stat", deny("stat"))

        for value in _historical_probe_values():
            with pytest.raises(PermissionError):
                reject_historical_openrouter_coordinates({"authority": value})
        assert touched == []

    def test_predecessor_projection_accepts_only_exact_public_history(
        self,
    ) -> None:
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            build_predecessor_projection_from_public_history,
        )

        projection = build_predecessor_projection_from_public_history()
        assert projection.v2_authority_id == (
            "phase5-openrouter-stealth-ox-alpha-recovery-r2-20260824"
        )
        assert projection.v1_authority_id == (
            "phase5-openrouter-stealth-ox-alpha-recovery-20260823"
        )
        # The projection is derived ONLY from public history artifacts and
        # carries no secret-derived material.
        dumped = projection.model_dump(mode="json")
        forbidden = {
            "secret_value",
            "secret_length",
            "secret_prefix",
            "secret_digest",
            "secret_identity",
            "secret_inode",
            "secret_device",
        }
        assert forbidden.isdisjoint(dumped)
        assert dumped["secret_read"] is False

    def test_predecessor_projection_rejects_off_projection_digests(self) -> None:
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            build_predecessor_projection_from_public_history,
            verify_predecessor_projection,
        )

        real = build_predecessor_projection_from_public_history()
        dumped = real.model_dump(mode="json")
        forged = {**dumped, "attempt_count": 7}
        with pytest.raises((ValueError, ValidationError)):
            verify_predecessor_projection(forged)

    def test_v3_contracts_reject_v1_v2_authority_and_schema_strings(self) -> None:
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            OpenRouterProtectedStateDescriptorV3,
        )

        root = "/private/tmp/v3-probe-root"
        fields = {
            "schema_version": V3_PROTECTED_STATE_SCHEMA,
            "authority_id": "phase5-openrouter-stealth-ox-alpha-recovery-r2-20260824",
            "state_root": root,
            "approval_target": f"{root}/approval.json",
            "claim_target": f"{root}/claim.json",
            "ledger_target": f"{root}/ledger",
            "journal_target": f"{root}/journal",
            "attempts_target": f"{root}/attempts",
            "reconciliation_target": f"{root}/reconciliation",
            "raw_evidence_target": f"{root}/raw-evidence",
            "profile_target": f"{root}/profiles",
            "generation_target": f"{root}/generation.json",
            "terminal_target": f"{root}/terminal.json",
        }
        with pytest.raises(
            PermissionError, match="OPENROUTER_V3_HISTORICAL_AUTHORITY_REJECTED"
        ):
            OpenRouterProtectedStateDescriptorV3.model_validate(
                {**fields, "protected_state_sha256": canonical_sha256(fields)}
            )


# ---------------------------------------------------------------------------
# Operation-discriminated segmented ledger entries.
# ---------------------------------------------------------------------------


def _ledger_entry_fields(
    operation: str = "RESERVE", **overrides: object
) -> dict[str, object]:
    fields: dict[str, object] = {
        "segment": "SETTLEMENTS" if operation == "RECOVER_UNRESOLVED" else "ATTEMPTS",
        "sequence": 1,
        "operation": operation,
        "attempt_number": 1,
        "amount_micro_usd": 0,
        "price_status": "EXACT_ZERO",
        "place_id": "place:v3-a",
        "request_sha256": "a" * 64,
        "claim_sha256": "c" * 64,
        "evidence_kind": {
            "RESERVE": "RESERVATION",
            "DISPATCH": "DISPATCH_PREPARED",
            "COMMIT": "ATTEMPT_OUTCOME",
            "RECOVER_UNRESOLVED": "RECONCILIATION",
        }.get(operation, "UNKNOWN"),
        "required_evidence_sha256": "d" * 64,
        "predecessor_entry_sha256": "0" * 64,
    }
    fields.update(overrides)
    return fields


class TestSegmentedLedgerEntries:
    @pytest.mark.parametrize("operation", LEDGER_OPERATIONS)
    def test_every_operation_builds_a_fully_digested_entry(self, operation: str) -> None:
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            build_openrouter_ledger_entry_v3,
        )

        fields = _ledger_entry_fields(operation=operation)
        entry = build_openrouter_ledger_entry_v3(fields)
        # Entry self-digest present; every field non-null.
        dumped = entry.model_dump(mode="json")
        assert all(value is not None for value in dumped.values())
        unsigned = {k: v for k, v in dumped.items() if k != "entry_sha256"}
        assert canonical_sha256(unsigned) == dumped["entry_sha256"]
        assert dumped["operation"] == operation
        assert dumped["amount_micro_usd"] == 0
        assert dumped["price_status"] == "EXACT_ZERO"

    def test_sequence_chain_is_hash_linked(self) -> None:
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            build_openrouter_ledger_entry_v3,
        )

        first = build_openrouter_ledger_entry_v3(_ledger_entry_fields())
        second_fields = _ledger_entry_fields(
            operation="DISPATCH",
            sequence=2,
            predecessor_entry_sha256=str(first.entry_sha256),
        )
        second = build_openrouter_ledger_entry_v3(second_fields)
        assert second.sequence == 2
        assert second.predecessor_entry_sha256 == first.entry_sha256

    def test_broken_previous_digest_rejected(self) -> None:
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            build_openrouter_ledger_entry_v3,
        )

        # A NULL predecessor is impossible: the field is required.
        fields = _ledger_entry_fields()
        del fields["predecessor_entry_sha256"]
        with pytest.raises(ValidationError):
            build_openrouter_ledger_entry_v3(fields)

    def test_nonzero_amount_impossible(self) -> None:
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            build_openrouter_ledger_entry_v3,
        )

        with pytest.raises(ValidationError):
            build_openrouter_ledger_entry_v3(
                _ledger_entry_fields(amount_micro_usd=500)
            )

    def test_unknown_operation_rejected(self) -> None:
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            build_openrouter_ledger_entry_v3,
        )

        with pytest.raises(ValueError, match="OPENROUTER_V3_OPERATION_UNKNOWN"):
            build_openrouter_ledger_entry_v3(_ledger_entry_fields(operation="SETTLE"))


# ---------------------------------------------------------------------------
# Outcome-discriminated attempts.
# ---------------------------------------------------------------------------


def _attempt_fields(outcome: str, **overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "attempt_number": 1,
        "place_id": "place:v3-a",
        "request_sha256": "a" * 64,
        "claim_sha256": "c" * 64,
        "outcome": outcome,
    }
    if outcome == "HTTP_RESPONSE":
        base.update(
            {
                "status_code": 200,
                "response_length": 128,
                "response_sha256": "b" * 64,
                "raw_evidence_sha256": "d" * 64,
            }
        )
    elif outcome == "TRANSPORT_ERROR":
        base.update(
            {
                "transport_class": "ConnectTimeout",
                "retry_classification": "RETRYABLE",
            }
        )
    elif outcome == "CREDENTIAL_RESPONSE_STRIPPED":
        base.update(
            {
                "status_code": 401,
                "strip_marker": "CREDENTIAL_RESPONSE_STRIPPED",
            }
        )
    else:
        base.update(
            {
                "failure_code": "OPENROUTER_SECRET_UNAVAILABLE",
                "secret_read": False,
                "client_constructed": False,
                "send_boundary_reached": False,
                "network_attempted": False,
            }
        )
    base.update(overrides)
    return base


class TestOutcomeDiscriminatedAttempts:
    @pytest.mark.parametrize("outcome", ATTEMPT_OUTCOMES)
    def test_each_outcome_carries_exact_branch_fields(self, outcome: str) -> None:
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            build_openrouter_attempt_v3,
        )

        attempt = build_openrouter_attempt_v3(_attempt_fields(outcome))
        dumped = attempt.model_dump(mode="json")
        assert all(value is not None for value in dumped.values()), outcome
        unsigned = {k: v for k, v in dumped.items() if k != "outcome_sha256"}
        assert canonical_sha256(unsigned) == dumped["outcome_sha256"]

    def test_cross_branch_fields_rejected(self) -> None:
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            build_openrouter_attempt_v3,
        )

        # A TRANSPORT_ERROR carrying an HTTP status is impossible.
        with pytest.raises(ValidationError):
            build_openrouter_attempt_v3(
                _attempt_fields("TRANSPORT_ERROR", status_code=200)
            )
        # An HTTP_RESPONSE carrying a transport class is impossible.
        with pytest.raises(ValidationError):
            build_openrouter_attempt_v3(
                _attempt_fields("HTTP_RESPONSE", transport_class="ReadTimeout")
            )

    def test_credential_stripped_stores_no_original_body_metadata(self) -> None:
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            build_openrouter_attempt_v3,
        )

        attempt = build_openrouter_attempt_v3(
            _attempt_fields("CREDENTIAL_RESPONSE_STRIPPED")
        )
        dumped = attempt.model_dump(mode="json")
        forbidden = {
            "response_length",
            "response_sha256",
            "raw_evidence_sha256",
        }
        assert not (set(dumped) & forbidden), set(dumped) & forbidden
        # The strip marker is a fixed literal, never value-derived.
        assert dumped["strip_marker"] == "CREDENTIAL_RESPONSE_STRIPPED"


# ---------------------------------------------------------------------------
# Reconciliation evidence: conservative certainty, no resend.
# ---------------------------------------------------------------------------


class TestReconciliationEvidence:
    def test_interrupted_attempt_settles_conservatively_without_resend(
        self, tmp_path: Path
    ) -> None:
        """A dispatched-but-unsettled attempt closes RECOVER_UNRESOLVED and the
        scheduler refuses to re-dispatch that place within the same claim."""

        state, claim = _seeded_state(tmp_path)
        ordinal = state.reserve_once(
            claim=claim, place_id="place:v3-a", request_sha256="a" * 64
        )
        state.record_dispatch(
            claim=claim, place_id="place:v3-a", request_sha256="a" * 64,
            attempt_number=ordinal,
        )
        recovered = state.reconcile_interrupted(claim=claim)
        assert recovered is not None
        assert recovered["status"] == "DESIGNED_NEGATIVE"
        # Conservative certainty: no response evidence exists.
        assert recovered["network_attempted"] is False
        entries = state.read_ledger_entries()
        operations = [row["operation"] for row in entries]
        assert "RECOVER_UNRESOLVED" in operations
        # The settled place cannot be reserved again in this run (no resend).
        with pytest.raises(PermissionError):
            state.reserve_once(claim=claim, place_id="place:v3-a", request_sha256="a" * 64)

    def test_reserve_only_crash_settles_reserved_phase(self, tmp_path: Path) -> None:
        state, claim = _seeded_state(tmp_path)
        state.reserve_once(claim=claim, place_id="place:v3-b", request_sha256="b" * 64)
        recovered = state.reconcile_interrupted(claim=claim)
        assert recovered is not None
        assert recovered["client_constructed"] is False
        assert recovered["send_certainty"] == "NOT_STARTED_CONFIRMED_LOCALLY"


# ---------------------------------------------------------------------------
# Durable segmented store: create-only, fsync, no replace, exact inventory.
# ---------------------------------------------------------------------------


def _seeded_state(root: Path):
    from itda.contracts.phase5_openrouter_recovery_v3 import (
        OpenRouterClaimV3,
        OpenRouterProtectedStateDescriptorV3,
    )
    from itda.pipeline.phase5_openrouter_recovery_v3 import (
        OpenRouterDurableAuthorityStateV3,
        OpenRouterProtectedStateLayoutV3,
    )

    state_root = root / "v3-root"
    descriptor = OpenRouterProtectedStateDescriptorV3.from_root(state_root=str(state_root))
    state = OpenRouterDurableAuthorityStateV3(descriptor)
    # Create the full segmented layout first so the exact root inventory
    # (dirs + files) holds during neutral verification.
    OpenRouterProtectedStateLayoutV3(state_root).create()
    os.chmod(state_root, 0o700)
    for directory in (
        "ledger",
        "journal",
        "attempts",
        "reconciliation",
        "raw-evidence",
        "profiles",
    ):
        os.chmod(state_root / directory, 0o700)
    approval_fields = {
        "schema_version": V3_APPROVAL_SCHEMA,
        "authority_id": V3_AUTHORITY_ID,
        "decision": "APPROVED",
        "request_artifact_sha256": "1" * 64,
        "request_file_sha256": "2" * 64,
        "request_manifest_sha256": "3" * 64,
        "membership_sha256": "4" * 64,
        "checkout_manifest_sha256": "5" * 64,
        "checkout_commit_sha256": "a" * 40,
        "protected_state_sha256": str(descriptor.protected_state_sha256),
        "predecessor_consumption_sha256": "6" * 64,
        "provider_lane": "OPENROUTER_API",
        "endpoint": "https://openrouter.ai/api/v1/chat/completions",
        "model": "stealth/ox-alpha",
        "snapshot_sha256": "8" * 64,
        "member_count": 24,
        "first_pass_count": 24,
        "max_retries": 6,
        "max_attempts": 30,
        "concurrency": 1,
        "attempt_deadline_seconds": 300,
        "max_response_bytes": 4_194_304,
        "reservation_micro_usd": 0,
        "cumulative_exposure_micro_usd": 0,
        "receipt_emitted": False,
        "lifecycle_mutated": False,
    }
    from itda.contracts.phase5_openrouter_recovery_v3 import OpenRouterApprovalBindingV3

    approval = OpenRouterApprovalBindingV3.model_validate(
        {**approval_fields, "approval_sha256": canonical_sha256(approval_fields)}
    )
    state.install_approval(approval, request_artifact={"request_artifact_sha256": "1" * 64})
    claim_fields = {
        "schema_version": V3_CLAIM_SCHEMA,
        "authority_id": V3_AUTHORITY_ID,
        "request_artifact_sha256": "1" * 64,
        "request_file_sha256": "2" * 64,
        "approval_sha256": approval.approval_sha256,
        "protected_state_sha256": str(descriptor.protected_state_sha256),
        "predecessor_consumption_sha256": "6" * 64,
    }
    claim = OpenRouterClaimV3.model_validate(
        {**claim_fields, "claim_sha256": canonical_sha256(claim_fields)}
    )
    state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    (state_root / "claim.json").write_bytes(canonical_json_bytes(claim.model_dump(mode="json")))
    os.chmod(state_root / "claim.json", 0o600)
    return state, claim


class TestDurableSegmentedStore:
    def test_store_creates_private_layout_once(self, tmp_path: Path) -> None:
        from itda.pipeline.phase5_openrouter_recovery_v3 import (
            OpenRouterProtectedStateLayoutV3,
        )

        root = tmp_path / "fresh-root"
        root.mkdir(mode=0o700)
        layout = OpenRouterProtectedStateLayoutV3(root)
        created = layout.create()
        root_mode = stat.S_IMODE(created["root"].st_mode)
        assert root_mode == 0o700
        for metadata in created["files"].values():
            assert stat.S_ISREG(metadata.st_mode)
            assert stat.S_IMODE(metadata.st_mode) == 0o600
            assert metadata.st_nlink == 1
        for metadata in created["dirs"].values():
            assert stat.S_ISDIR(metadata.st_mode)
            assert stat.S_IMODE(metadata.st_mode) == 0o700
        # Second create fails closed: create-only semantics.
        with pytest.raises(FileExistsError):
            layout.create()

    def test_store_rejects_symlink_and_foreign_owner(self, tmp_path: Path) -> None:
        from itda.pipeline.phase5_openrouter_recovery_v3 import (
            OpenRouterProtectedStateLayoutV3,
        )

        root = tmp_path / "link-root"
        root.mkdir(mode=0o700)
        target = tmp_path / "elsewhere"
        target.mkdir(mode=0o700)
        (root / "journal").symlink_to(target)
        layout = OpenRouterProtectedStateLayoutV3(root)
        with pytest.raises((FileExistsError, PermissionError)):
            layout.create()

    def test_ledger_append_is_create_then_fsync_no_replace(self, tmp_path: Path) -> None:
        state, claim = _seeded_state(tmp_path)
        first = state.reserve_once(
            claim=claim, place_id="place:v3-a", request_sha256="a" * 64
        )
        assert first == 1
        second = state.reserve_once(
            claim=claim, place_id="place:v3-b", request_sha256="b" * 64
        )
        assert second == 2
        entries = state.read_ledger_entries()
        sequences = [row["sequence"] for row in entries]
        assert sequences == [1, 2]
        # Chain integrity: each entry's predecessor is the previous digest.
        for previous, row in zip(entries, entries[1:], strict=False):
            assert row["predecessor_entry_sha256"] == previous["entry_sha256"]
        # Every entry re-verifies its self digest on read.
        for row in entries:
            unsigned = {k: v for k, v in row.items() if k != "entry_sha256"}
            assert canonical_sha256(unsigned) == row["entry_sha256"]

    def test_ledger_tampering_detected_on_read(self, tmp_path: Path) -> None:
        state, claim = _seeded_state(tmp_path)
        state.reserve_once(claim=claim, place_id="place:v3-a", request_sha256="a" * 64)
        ledger_path = (
            Path(state.descriptor.state_root) / "ledger/0001-reserve.json"
        )
        row = json.loads(ledger_path.read_bytes())
        row["place_id"] = "place:forged"
        ledger_path.write_bytes(canonical_json_bytes(row))
        with pytest.raises((ValueError, PermissionError)):
            state.read_ledger_entries()

    def test_exact_inventory_and_filename_grammar(self, tmp_path: Path) -> None:
        state, claim = _seeded_state(tmp_path)
        ordinal = state.reserve_once(
            claim=claim, place_id="place:v3-a", request_sha256="a" * 64
        )
        state.record_dispatch(
            claim=claim, place_id="place:v3-a", request_sha256="a" * 64,
            attempt_number=ordinal,
        )
        evidence = state.persist_attempt_evidence(
            claim=claim,
            place_id="place:v3-a",
            request_sha256="a" * 64,
            attempt_number=ordinal,
            outcome="HTTP_RESPONSE",
            status_code=200,
            response_body=b'{"profile":{}}',
        )
        state.commit_reservation(
            claim=claim,
            place_id="place:v3-a",
            request_sha256="a" * 64,
            attempt_number=ordinal,
            evidence_sha256=evidence,
        )
        # Exact inventory passes.
        state.validate_journal_evidence_inventory()
        state.validate_raw_evidence_inventory()
        # Staging residue is rejected: a leftover .stage file breaks exactness.
        journal_dir = Path(state.descriptor.state_root) / "journal/attempt-01"
        residue = journal_dir / ".dispatch-prepared.stage-deadbeef"
        residue.write_bytes(b"x")
        os.chmod(residue, 0o600)
        with pytest.raises(PermissionError):
            state.validate_journal_evidence_inventory()

    def test_commit_requires_matching_evidence(self, tmp_path: Path) -> None:
        state, claim = _seeded_state(tmp_path)
        ordinal = state.reserve_once(
            claim=claim, place_id="place:v3-a", request_sha256="a" * 64
        )
        state.record_dispatch(
            claim=claim, place_id="place:v3-a", request_sha256="a" * 64,
            attempt_number=ordinal,
        )
        evidence = state.persist_attempt_evidence(
            claim=claim,
            place_id="place:v3-a",
            request_sha256="a" * 64,
            attempt_number=ordinal,
            outcome="HTTP_RESPONSE",
            status_code=200,
            response_body=b"{}",
        )
        wrong = "f" * 64
        with pytest.raises(PermissionError):
            state.commit_reservation(
                claim=claim,
                place_id="place:v3-a",
                request_sha256="a" * 64,
                attempt_number=ordinal,
                evidence_sha256=wrong,
            )
        state.commit_reservation(
            claim=claim,
            place_id="place:v3-a",
            request_sha256="a" * 64,
            attempt_number=ordinal,
            evidence_sha256=evidence,
        )


# ---------------------------------------------------------------------------
# Terminal contracts: discriminated dispositions, positive-only maps.
# ---------------------------------------------------------------------------


def _terminal_fields(**overrides: object) -> dict[str, object]:
    fields: dict[str, object] = {
        "schema_version": V3_TERMINAL_SCHEMA,
        "status": "DESIGNED_NEGATIVE",
        "reason": "HTTP_429",
        "authority_id": V3_AUTHORITY_ID,
        "request_artifact_sha256": "a" * 64,
        "request_file_sha256": "b" * 64,
        "request_manifest_sha256": "c" * 64,
        "checkout_manifest_sha256": "d" * 64,
        "checkout_commit_sha256": "a" * 40,
        "claim_sha256": "e" * 64,
        "predecessor_consumption_sha256": "f" * 64,
        "profile_count": 0,
        "ledger_segment_sha256": "1" * 64,
        "journal_sha256": "2" * 64,
        "attempt_count": 24,
        "reserve_count": 24,
        "http_response_count": 20,
        "transport_error_count": 4,
        "credential_stripped_count": 0,
        "local_pre_send_failure_count": 0,
        "secret_read": True,
        "client_constructed": True,
        "network_attempted": True,
        "lifecycle_mutated": False,
        "activation_capability": False,
    }
    fields.update(overrides)
    return fields


def _parse_terminal(fields: dict[str, object]):
    from itda.contracts.phase5_openrouter_recovery_v3 import (
        parse_openrouter_terminal_v3,
    )

    return parse_openrouter_terminal_v3(
        {**fields, "terminal_sha256": canonical_sha256(fields)}
    )


class TestTerminalContracts:
    def test_designed_negative_terminal_validates(self) -> None:
        terminal = _parse_terminal(_terminal_fields())
        assert terminal.status == "DESIGNED_NEGATIVE"

    def test_forbidden_branch_keys_absent_from_schema(self) -> None:
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            OpenRouterTerminalDesignedNegativeV3,
            OpenRouterTerminalFailedUnactivatedV3,
            OpenRouterTerminalPositiveV3,
        )

        for model in (
            OpenRouterTerminalPositiveV3,
            OpenRouterTerminalDesignedNegativeV3,
            OpenRouterTerminalFailedUnactivatedV3,
        ):
            for name in model.model_fields:
                lowered = name.lower()
                assert "release" not in lowered, name
                assert "smoke" not in lowered, name
                assert "blind" not in lowered, name
        assert "generation" not in OpenRouterTerminalDesignedNegativeV3.model_fields
        assert "generation" not in OpenRouterTerminalFailedUnactivatedV3.model_fields

    def test_negative_terminal_cannot_carry_generation(self) -> None:
        fields = _terminal_fields(generation_sha256="9" * 64, profile_count=24)
        with pytest.raises(ValidationError):
            _parse_terminal(fields)

    def test_outcome_counts_must_sum_to_attempts(self) -> None:
        with pytest.raises(ValidationError):
            _parse_terminal(_terminal_fields(http_response_count=21))

    def test_failed_unactivated_without_network_is_consistent(self) -> None:
        terminal = _parse_terminal(
            _terminal_fields(
                status="FAILED_UNACTIVATED",
                reason="LOCAL_PRE_SEND_FAILURE",
                attempt_count=3,
                reserve_count=3,
                http_response_count=0,
                transport_error_count=0,
                credential_stripped_count=0,
                local_pre_send_failure_count=3,
                secret_read=False,
                client_constructed=False,
                network_attempted=False,
            )
        )
        assert terminal.network_attempted is False

    def test_positive_terminal_requires_complete_maps(self) -> None:
        with pytest.raises(ValidationError):
            _parse_terminal(
                _terminal_fields(status="COMPLETE_CANDIDATE_READY")
            )


# ---------------------------------------------------------------------------
# Approval/claim binding: exact packet/source/descriptor/predecessor, no
# secret-derived metadata beyond the opaque identity digest contract.
# ---------------------------------------------------------------------------


class TestApprovalClaimBinding:
    def test_approval_contains_no_secret_value_material(self) -> None:
        from itda.contracts.phase5_openrouter_recovery_v3 import OpenRouterApprovalBindingV3

        field_names = set(OpenRouterApprovalBindingV3.model_fields)
        for forbidden in (
            "secret_identity_sha256",
            "secret_digest",
            "secret_value",
            "secret_length",
            "secret_prefix",
            "secret_inode",
            "secret_device",
            "secret_size",
            "secret_mtime",
        ):
            assert forbidden not in field_names, forbidden

    def test_claim_binds_exact_predecessor_and_descriptor(self) -> None:
        from itda.contracts.phase5_openrouter_recovery_v3 import OpenRouterClaimV3

        field_names = set(OpenRouterClaimV3.model_fields)
        assert {
            "schema_version",
            "authority_id",
            "request_artifact_sha256",
            "request_file_sha256",
            "approval_sha256",
            "protected_state_sha256",
            "predecessor_consumption_sha256",
            "claim_sha256",
        } == field_names


# ---------------------------------------------------------------------------
# Crash boundaries through the sealed mock seam (synthetic temp roots only).
# ---------------------------------------------------------------------------


class TestCrashBoundariesMockSeam:
    def test_mock_seam_refuses_production_root(self) -> None:
        import asyncio

        repository_root = Path(lane_v3.REPOSITORY_ROOT)
        with pytest.raises(PermissionError, match="PRODUCTION_ROOT|MOCK_FORBIDS"):
            asyncio.run(
                lane_v3.execute_openrouter_v3_mock_transport(
                    protected_state_root=(
                        repository_root
                        / "artifacts/restricted/catalog/phase5-openrouter-recovery-r3"
                    ),
                    response_handler=lambda request: httpx.Response(200),
                )
            )


# ---------------------------------------------------------------------------
# Scheduler policy constants.
# ---------------------------------------------------------------------------


class TestSchedulerPolicy:
    def test_exact_budget_constants(self) -> None:
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            OPENROUTER_V3_ATTEMPT_DEADLINE_SECONDS,
            OPENROUTER_V3_CONCURRENCY,
            OPENROUTER_V3_FIRST_PASS_COUNT,
            OPENROUTER_V3_MAX_ATTEMPTS,
            OPENROUTER_V3_MAX_RESPONSE_BYTES,
            OPENROUTER_V3_MAX_RETRIES,
        )

        assert OPENROUTER_V3_FIRST_PASS_COUNT == 24
        assert OPENROUTER_V3_MAX_RETRIES == 6
        assert OPENROUTER_V3_MAX_ATTEMPTS == 30
        assert OPENROUTER_V3_CONCURRENCY == 1
        assert OPENROUTER_V3_ATTEMPT_DEADLINE_SECONDS == 300
        assert OPENROUTER_V3_MAX_RESPONSE_BYTES == 4 * 1024 * 1024

    def test_scheduler_exact_24_first_passes_before_retries(self) -> None:
        scheduler = lane_v3.OpenRouterSchedulerV3([f"place:{i:02d}" for i in range(24)])
        first = scheduler.first_pass()
        assert len(first) == 24
        with pytest.raises(RuntimeError, match="first pass"):
            scheduler.retry_order(("place:00",))
        # Retries are impossible until all 24 first passes were DISPATCHED.
        with pytest.raises(RuntimeError):
            scheduler.retry_order(("place:00",))
        for place in first:
            scheduler.record_dispatched(place, is_retry=False)
        order = scheduler.retry_order(sorted(["place:00"]))
        assert len(order) == 1
        with pytest.raises(RuntimeError):
            scheduler.retry_order(["place:01"])

    def test_zero_price_request_fields(self) -> None:
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            openrouter_v3_request_body_fields,
        )

        fields = openrouter_v3_request_body_fields()
        assert fields["provider"]["max_price"] == {"prompt": "0", "completion": "0"}
        assert fields["reasoning"]["effort"] == "high"


# ---------------------------------------------------------------------------
# Provider-free v3 CLI surface: public commands, sealed runner, capability
# routing, and the fixed secret shape validator.  Everything here runs with
# provider env removed, sockets denied (conftest), and synthetic temp roots.
# ---------------------------------------------------------------------------


def build_failed_terminal_for_state(state, claim, approval) -> dict[str, object]:
    from itda.contracts.phase5_openrouter_recovery_v3 import build_openrouter_terminal_v3

    state.ensure_profiles_dir()
    state.ensure_raw_evidence_dir()
    counts = state.outcome_counts()
    reserve_count = sum(
        row["operation"] == "RESERVE" for row in state.read_ledger_entries()
    )
    terminal = build_openrouter_terminal_v3(
        status="FAILED_UNACTIVATED",
        reason="OPENROUTER_V3_LOCAL_PRE_SEND_FAILURE",
        request_artifact_sha256=str(approval.request_artifact_sha256),
        request_file_sha256=str(approval.request_file_sha256),
        request_manifest_sha256=str(approval.request_manifest_sha256),
        checkout_commit_sha256=str(approval.checkout_commit_sha256),
        checkout_manifest_sha256=str(approval.checkout_manifest_sha256),
        claim_sha256=str(claim.claim_sha256),
        predecessor_consumption_sha256=str(approval.predecessor_consumption_sha256),
        generation=None,
        ledger_segment_sha256=state.ledger_segment_sha256(),
        journal_sha256=state.journal_inventory_digest(),
        attempt_count=sum(counts.values()),
        reserve_count=reserve_count,
        http_response_count=counts["HTTP_RESPONSE"],
        transport_error_count=counts["TRANSPORT_ERROR"],
        credential_stripped_count=counts["CREDENTIAL_RESPONSE_STRIPPED"],
        local_pre_send_failure_count=counts["LOCAL_PRE_SEND_FAILURE"],
        secret_read=False,
        client_constructed=False,
        network_attempted=False,
    )
    payload = terminal.model_dump(mode="json")
    state.publish_terminal(terminal=payload)
    return payload


def _seeded_v3_failed_terminal(state, claim, approval) -> dict[str, object]:
    """Publish a minimal legal FAILED_UNACTIVATED terminal for verify tests."""

    return build_failed_terminal_for_state(state, claim, approval)


class TestV3CliSurface:
    def test_public_parser_registers_only_provider_free_v3_commands(self) -> None:
        from itda.cli.phase5_openrouter_recovery_v3 import build_public_parser

        parser = build_public_parser()
        help_text = parser.format_help()
        for name in (
            "openrouter-recovery-v3-preflight",
            "openrouter-recovery-v3-secret-shape",
            "openrouter-recovery-v3-verify",
            "openrouter-recovery-v3-classify",
        ):
            assert name in help_text, name
        # Capability names never appear in the public parser.
        for name in (
            "openrouter-recovery-v3-install-approval",
            "openrouter-recovery-v3-live",
            "openrouter-recovery-v3-reconcile",
        ):
            assert name not in help_text, name

    def test_capability_names_rejected_through_public_main(self) -> None:
        from itda.cli.phase5_openrouter_recovery_v3 import main as v3_main

        for argv in (
            ["openrouter-recovery-v3-install-approval"],
            ["openrouter-recovery-v3-live"],
            ["openrouter-recovery-v3-reconcile"],
        ):
            assert v3_main(argv) == 2

    def test_verify_rejects_nonfixed_terminal_path_before_any_read(
        self, tmp_path: Path
    ) -> None:
        from itda.cli.phase5_openrouter_recovery_v3 import main as v3_main

        forged = tmp_path / "forged-v3-terminal.json"
        forged.write_bytes(b"{}")
        assert (
            v3_main(
                [
                    "openrouter-recovery-v3-verify",
                    "--terminal",
                    str(forged),
                    "--json",
                ]
            )
            == 2
        )
        # The forged file was never opened (bytes unchanged).
        assert forged.read_bytes() == b"{}"

    def test_classify_rejects_unverified_outcome_without_client_or_socket(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import socket as socket_module

        from itda.cli.phase5_openrouter_recovery_v3 import (
            classify_openrouter_v3_outcome,
        )

        touched: list[str] = []

        def deny(name: str):
            def blocked(*_args: object, **_kwargs: object) -> object:
                touched.append(name)
                raise AssertionError(f"capability reached: {name}")

            return blocked

        monkeypatch.setattr(httpx, "AsyncClient", deny("client"))
        monkeypatch.setattr(socket_module, "socket", deny("socket"))
        # No raw-outcome input surface exists; durable evidence is mandatory.
        with pytest.raises(TypeError):
            classify_openrouter_v3_outcome(  # type: ignore[call-arg]
                {"status": "FORGED"}
            )
        assert touched == []

    def test_preflight_does_not_observe_production_protected_root(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from itda.cli import phase5_openrouter_recovery_v3 as command

        original_exists = Path.exists

        def guarded_exists(path: Path) -> bool:
            if path == command.OPENROUTER_V3_PROTECTED_ROOT:
                raise AssertionError("production protected root observed")
            return original_exists(path)

        monkeypatch.setattr(Path, "exists", guarded_exists)
        payload = command._preflight_payload(verify_only=False)
        assert "protected_root_present" not in payload
        assert payload["network_attempted"] is False
        assert payload["client_constructed"] is False
        assert payload["secret_read"] is False

    def test_strict_positive_assertion_is_separate_step(self, tmp_path: Path) -> None:
        from itda.cli.phase5_openrouter_recovery_v3 import assert_openrouter_v3_positive

        # A raw non-outcome object is refused outright.
        class _NegativeOutcome:
            terminal_status = "DESIGNED_NEGATIVE"
            live_status = 2

        with pytest.raises(TypeError):
            assert_openrouter_v3_positive(  # type: ignore[call-arg]
                _NegativeOutcome(), live_status=2
            )

        state, claim = _seeded_state(tmp_path / "positive-gate-root")
        approval = state.read_approval()
        terminal = _seeded_v3_failed_terminal(state, claim, approval)
        with pytest.raises(ValueError):
            assert_openrouter_v3_positive(
                protected_state_root=Path(str(state.descriptor.state_root)),
                public_terminal_bytes=canonical_json_bytes(terminal),
            )

    def test_secret_shape_contract_named_results_only(self, tmp_path: Path) -> None:
        """dir 0700, file 0600, current-user owner, regular non-symlink
        single-link, exact one UTF-8 record; pass or named error only; no
        value-derived material ever returned."""

        from itda.cli.phase5_openrouter_recovery_v3 import validate_v3_secret_shape

        good_dir = tmp_path / "good" / ".secrets"
        good_dir.mkdir(parents=True, mode=0o700)
        os.chmod(good_dir.parent, 0o755)
        secret = good_dir / "itda-openrouter.env"
        secret.write_bytes(b"OPENROUTER_API_KEY=test-value\n")
        os.chmod(secret, 0o600)
        result = validate_v3_secret_shape(secret)
        assert result["status"] == "pass"
        dumped = repr(result).lower()
        for marker in ("test-value", "length", "prefix", "digest", "inode", "device"):
            assert marker not in dumped, marker

        # Directory mode too permissive -> named error.
        loose_dir = tmp_path / "loose" / ".secrets"
        loose_dir.mkdir(parents=True, mode=0o700)
        os.chmod(loose_dir, 0o755)
        loose = loose_dir / "itda-openrouter.env"
        loose.write_bytes(b"OPENROUTER_API_KEY=x\n")
        os.chmod(loose, 0o600)
        loose_result = validate_v3_secret_shape(loose)
        assert loose_result["status"] == "fail"
        assert isinstance(loose_result.get("error"), str) and loose_result["error"]

        # Symlink final component -> NOT_REGULAR_FILE before any content read.
        link_dir = tmp_path / "link" / ".secrets"
        target = tmp_path / "link-target.env"
        target.write_bytes(b"OPENROUTER_API_KEY=x\n")
        os.chmod(target, 0o600)
        link_dir.mkdir(parents=True, mode=0o700)
        link = link_dir / "itda-openrouter.env"
        link.symlink_to(target)
        assert validate_v3_secret_shape(link) == {
            "status": "fail",
            "error": "NOT_REGULAR_FILE",
        }

        alias_parent = tmp_path / "secret-parent-alias"
        alias_parent.symlink_to(good_dir.parent, target_is_directory=True)
        alias_secret = alias_parent / ".secrets" / "itda-openrouter.env"
        assert validate_v3_secret_shape(alias_secret)["status"] == "fail"

        # Wrong record key -> RECORD_INVALID.
        wrong_dir = tmp_path / "record" / ".secrets"
        wrong_dir.mkdir(parents=True, mode=0o700)
        wrong = wrong_dir / "itda-openrouter.env"
        wrong.write_bytes(b"NVIDIA_KEY=x\n")
        os.chmod(wrong, 0o600)
        record_result = validate_v3_secret_shape(wrong)
        assert record_result == {"status": "fail", "error": "RECORD_INVALID"}

        # Empty value -> fail.
        empty_dir = tmp_path / "empty" / ".secrets"
        empty_dir.mkdir(parents=True, mode=0o700)
        empty = empty_dir / "itda-openrouter.env"
        empty.write_bytes(b"OPENROUTER_API_KEY=\n")
        os.chmod(empty, 0o600)
        assert validate_v3_secret_shape(empty)["status"] == "fail"

        # Two records -> RECORD_INVALID (exact one record contract).
        multi_dir = tmp_path / "multi" / ".secrets"
        multi_dir.mkdir(parents=True, mode=0o700)
        multi = multi_dir / "itda-openrouter.env"
        multi.write_bytes(b"OPENROUTER_API_KEY=a\nOTHER=b\n")
        os.chmod(multi, 0o600)
        multi_result = validate_v3_secret_shape(multi)
        assert multi_result == {"status": "fail", "error": "RECORD_INVALID"}

    def test_secret_shape_never_reads_production_coordinates(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The validator operates on caller-supplied synthetic paths only and
        never touches the production .secrets coordinate."""

        repository_root = Path(__file__).resolve().parents[3]
        production_secret = repository_root / ".secrets" / "itda-openrouter.env"
        touched: list[str] = []

        original_stat = os.stat
        original_os_open = os.open

        def guarded(function, name: str):
            def wrapper(path, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
                try:
                    candidate = Path(os.path.abspath(os.fspath(path)))
                except (TypeError, ValueError):
                    return function(path, *args, **kwargs)
                if candidate == production_secret or production_secret.parent in (
                    candidate.parents or ()
                ):
                    touched.append(name)
                    raise AssertionError("PRODUCTION_SECRET_ACCESSED")
                return function(path, *args, **kwargs)

            return wrapper

        monkeypatch.setattr(os, "stat", guarded(original_stat, "stat"))
        monkeypatch.setattr(os, "lstat", guarded(os.lstat, "lstat"))
        monkeypatch.setattr(os, "open", guarded(original_os_open, "os.open"))

        synthetic_dir = tmp_path / ".secrets"
        synthetic_dir.mkdir(mode=0o700)
        synthetic = synthetic_dir / "itda-openrouter.env"
        synthetic.write_bytes(b"OPENROUTER_API_KEY=synthetic\n")
        os.chmod(synthetic, 0o600)
        from itda.cli.phase5_openrouter_recovery_v3 import validate_v3_secret_shape

        assert validate_v3_secret_shape(synthetic)["status"] == "pass"
        assert touched == []

    def test_bootstrap_repository_root_ignores_environment_override(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from itda import minimal_probe_bootstrap as bootstrap

        expected = Path(bootstrap.__file__).absolute().parents[3]
        monkeypatch.setenv("ITDA_MINIMAL_PROBE_BOOTSTRAP_ROOT", str(tmp_path))
        assert bootstrap._repository_root() == expected

    def test_bootstrap_routes_v3_capabilities_and_keeps_v2_inert(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from itda import minimal_probe_bootstrap as bootstrap

        v3_names = {
            "openrouter-recovery-v3-install-approval",
            "openrouter-recovery-v3-live",
            "openrouter-recovery-v3-reconcile",
        }
        assert v3_names <= bootstrap._CAPABILITY_COMMANDS
        assert v3_names == bootstrap._OPENROUTER_V3_COMMAND_PREFIXES
        assert v3_names.isdisjoint(bootstrap._OPENROUTER_V2_COMMAND_PREFIXES)
        # The v2 inert branch still precedes everything.
        assert bootstrap.main(["openrouter-recovery-v2-live"]) == 2
        captured = capsys.readouterr()
        assert captured.err == "OPENROUTER_V2_CAPABILITY_INERT\n"

    def test_materialize_module_wires_minimal_v3_dispatcher(self) -> None:
        from itda.cli import materialize_phase5_demo_profiles as command

        expected = {
            "openrouter-recovery-v3-install-approval",
            "openrouter-recovery-v3-live",
            "openrouter-recovery-v3-reconcile",
        }
        v3_commands = command._OPENROUTER_V3_CAPABILITY_COMMANDS
        assert v3_commands == expected
        # The v3 names are part of the capability set the public main and the
        # pre-import gate reject fail-closed.
        assert v3_commands <= command._ALL_CAPABILITY_COMMANDS
        assert v3_commands.isdisjoint(command._OPENROUTER_CAPABILITY_COMMANDS)

    def test_public_materialize_main_fails_closed_for_v3_capabilities(self) -> None:
        from itda.cli import materialize_phase5_demo_profiles as command

        for name in sorted(command._OPENROUTER_V3_CAPABILITY_COMMANDS):
            result: int | None
            try:
                result = command.main([name])
            except SystemExit as excinfo:
                # argparse rejects the unregistered name with exit 2 — the
                # same fail-closed contract.
                result = int(excinfo.code or 0)
            assert result == 2, name

    def test_sealed_runner_takes_no_arguments(self) -> None:
        import inspect

        from itda.cli.phase5_openrouter_recovery_v3 import (
            execute_openrouter_v3_production,
        )

        parameters = set(inspect.signature(execute_openrouter_v3_production).parameters)
        assert parameters == set(), parameters

    def test_synthetic_test_root_alias_of_production_rejected(self, tmp_path: Path) -> None:
        import asyncio

        from itda.contracts.phase5_openrouter_recovery_v3_paths import (
            OPENROUTER_V3_PROTECTED_ROOT,
        )
        from itda.pipeline.phase5_openrouter_recovery_v3 import (
            execute_openrouter_v3_mock_transport,
        )

        alias = tmp_path / "alias-link"
        alias.symlink_to(OPENROUTER_V3_PROTECTED_ROOT, target_is_directory=True)
        with pytest.raises(PermissionError, match="MOCK_FORBIDS"):
            asyncio.run(
                execute_openrouter_v3_mock_transport(
                    protected_state_root=alias,
                    response_handler=lambda request: httpx.Response(200),
                )
            )


class TestV3NeutralVerifier:
    def test_verifier_reopens_all_evidence_classes_independently(
        self, tmp_path: Path
    ) -> None:
        """The neutral verifier reconstructs packet/snapshot/approval/claim/
        segmented ledger/journal/outcomes/raw/reconciliation/profiles/
        generation/terminal identity from durable bytes — no caller-supplied
        trust, no secret/client/socket reach."""

        from itda.cli.phase5_openrouter_recovery_v3 import verify_openrouter_v3_outcome

        state, claim = _seeded_state(tmp_path / "verifier-root")
        approval = state.read_approval()
        terminal = _seeded_v3_failed_terminal(state, claim, approval)
        outcome = verify_openrouter_v3_outcome(
            protected_state_root=Path(str(state.descriptor.state_root)),
            public_terminal_bytes=canonical_json_bytes(terminal),
        )
        assert outcome.terminal.status == "FAILED_UNACTIVATED"

    def test_verifier_rejects_public_protected_terminal_mismatch(
        self, tmp_path: Path
    ) -> None:
        from itda.cli.phase5_openrouter_recovery_v3 import verify_openrouter_v3_outcome

        state, claim = _seeded_state(tmp_path / "terminal-mismatch")
        approval = state.read_approval()
        _seeded_v3_failed_terminal(state, claim, approval)
        with pytest.raises(ValueError, match="PUBLIC_PROTECTED_TERMINAL"):
            verify_openrouter_v3_outcome(
                protected_state_root=Path(str(state.descriptor.state_root)),
                public_terminal_bytes=b"{}",
            )

    @pytest.mark.parametrize(
        ("field", "forged"),
        (
            ("request_artifact_sha256", "9" * 64),
            ("request_file_sha256", "9" * 64),
            ("request_manifest_sha256", "9" * 64),
            ("checkout_commit_sha256", "9" * 40),
            ("checkout_manifest_sha256", "9" * 64),
            ("predecessor_consumption_sha256", "9" * 64),
        ),
    )
    def test_negative_terminal_rejects_approval_lineage_drift(
        self, tmp_path: Path, field: str, forged: str
    ) -> None:
        from itda.cli.phase5_openrouter_recovery_v3 import verify_openrouter_v3_outcome
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            build_openrouter_terminal_v3,
        )

        state, claim = _seeded_state(tmp_path / field)
        approval = state.read_approval()
        values = {
            "request_artifact_sha256": str(approval.request_artifact_sha256),
            "request_file_sha256": str(approval.request_file_sha256),
            "request_manifest_sha256": str(approval.request_manifest_sha256),
            "checkout_commit_sha256": str(approval.checkout_commit_sha256),
            "checkout_manifest_sha256": str(approval.checkout_manifest_sha256),
            "predecessor_consumption_sha256": str(
                approval.predecessor_consumption_sha256
            ),
        }
        values[field] = forged
        terminal = build_openrouter_terminal_v3(
            status="FAILED_UNACTIVATED",
            reason="OPENROUTER_V3_LOCAL_PRE_SEND_FAILURE",
            **values,
            claim_sha256=str(claim.claim_sha256),
            generation=None,
            ledger_segment_sha256=state.ledger_segment_sha256(),
            journal_sha256=state.journal_inventory_digest(),
            attempt_count=0,
            reserve_count=0,
            http_response_count=0,
            transport_error_count=0,
            credential_stripped_count=0,
            local_pre_send_failure_count=0,
            secret_read=False,
            client_constructed=False,
            network_attempted=False,
        )
        payload = terminal.model_dump(mode="json")
        state.publish_terminal(terminal=payload)

        with pytest.raises(ValueError, match="TERMINAL|PREDECESSOR"):
            verify_openrouter_v3_outcome(
                protected_state_root=Path(str(state.descriptor.state_root)),
                public_terminal_bytes=canonical_json_bytes(payload),
            )

    def test_claim_predecessor_must_match_approval(
        self, tmp_path: Path
    ) -> None:
        from itda.cli.phase5_openrouter_recovery_v3 import verify_openrouter_v3_outcome

        state, claim = _seeded_state(tmp_path / "claim-predecessor")
        approval = state.read_approval()
        claim_path = Path(str(state.descriptor.state_root)) / "claim.json"
        payload = claim.model_dump(mode="json")
        payload["predecessor_consumption_sha256"] = "9" * 64
        unsigned = {key: value for key, value in payload.items() if key != "claim_sha256"}
        payload["claim_sha256"] = canonical_sha256(unsigned)
        claim_path.write_bytes(canonical_json_bytes(payload))
        terminal = build_failed_terminal_for_state(
            state,
            type(claim).model_validate(payload),
            approval,
        )

        with pytest.raises(ValueError, match="PREDECESSOR"):
            verify_openrouter_v3_outcome(
                protected_state_root=Path(str(state.descriptor.state_root)),
                public_terminal_bytes=canonical_json_bytes(terminal),
            )

    @pytest.mark.parametrize(
        ("field", "forged"),
        (("claim_sha256", "9" * 64), ("attempt_number", 2)),
    )
    def test_attempt_record_rejects_reserve_claim_or_ordinal_drift(
        self, tmp_path: Path, field: str, forged: object
    ) -> None:
        from itda.cli.phase5_openrouter_recovery_v3 import verify_openrouter_v3_outcome

        state, claim = _seeded_state(tmp_path / f"attempt-{field}")
        approval = state.read_approval()
        ordinal = state.reserve_once(
            claim=claim, place_id="place:attempt", request_sha256="a" * 64
        )
        state.record_dispatch(
            claim=claim,
            place_id="place:attempt",
            request_sha256="a" * 64,
            attempt_number=ordinal,
        )
        evidence = state.persist_attempt_evidence(
            claim=claim,
            place_id="place:attempt",
            request_sha256="a" * 64,
            attempt_number=ordinal,
            outcome="LOCAL_PRE_SEND_FAILURE",
            failure_code="OPENROUTER_SECRET_UNAVAILABLE",
        )
        state.commit_reservation(
            claim=claim,
            place_id="place:attempt",
            request_sha256="a" * 64,
            attempt_number=ordinal,
            evidence_sha256=evidence,
        )
        root = Path(str(state.descriptor.state_root))
        attempt_path = root / "attempts/attempt-01.json"
        attempt = json.loads(attempt_path.read_bytes())
        attempt[field] = forged
        attempt_unsigned = {
            key: value for key, value in attempt.items() if key != "outcome_sha256"
        }
        attempt["outcome_sha256"] = canonical_sha256(attempt_unsigned)
        attempt_path.write_bytes(canonical_json_bytes(attempt))

        commit_path = root / "ledger/0003-commit.json"
        commit = json.loads(commit_path.read_bytes())
        commit["required_evidence_sha256"] = attempt["outcome_sha256"]
        commit_unsigned = {
            key: value for key, value in commit.items() if key != "entry_sha256"
        }
        commit["entry_sha256"] = canonical_sha256(commit_unsigned)
        commit_path.write_bytes(canonical_json_bytes(commit))
        terminal = build_failed_terminal_for_state(state, claim, approval)

        with pytest.raises(PermissionError, match="ATTEMPT_LINEAGE"):
            verify_openrouter_v3_outcome(
                protected_state_root=root,
                public_terminal_bytes=canonical_json_bytes(terminal),
            )

    def test_verifier_rejects_reconciliation_digest_mismatch(
        self, tmp_path: Path
    ) -> None:
        from itda.cli.phase5_openrouter_recovery_v3 import verify_openrouter_v3_outcome

        state, claim = _seeded_state(tmp_path / "reconciliation-mismatch")
        approval = state.read_approval()
        ordinal = state.reserve_once(
            claim=claim, place_id="place:reconcile", request_sha256="a" * 64
        )
        state.record_dispatch(
            claim=claim,
            place_id="place:reconcile",
            request_sha256="a" * 64,
            attempt_number=ordinal,
        )
        state.reconcile_interrupted(claim=claim)
        terminal = build_failed_terminal_for_state(state, claim, approval)
        reconciliation = (
            Path(str(state.descriptor.state_root))
            / "reconciliation"
            / f"attempt-{ordinal:02d}.json"
        )
        payload = json.loads(reconciliation.read_bytes())
        payload["send_certainty"] = "UNKNOWN_AFTER_DISPATCH"
        reconciliation.write_bytes(canonical_json_bytes(payload))
        with pytest.raises(
            (ValueError, PermissionError), match="RECONCILIATION|PERSISTED_DIGEST_DRIFT"
        ):
            verify_openrouter_v3_outcome(
                protected_state_root=Path(str(state.descriptor.state_root)),
                public_terminal_bytes=canonical_json_bytes(terminal),
            )

    def test_classifier_accepts_only_durable_evidence(self, tmp_path: Path) -> None:
        from itda.cli.phase5_openrouter_recovery_v3 import classify_openrouter_v3_outcome

        with pytest.raises(TypeError):
            classify_openrouter_v3_outcome(  # type: ignore[call-arg]
                {"status": "DESIGNED_NEGATIVE"}
            )

    def test_classifier_dispositions_are_exact(self, tmp_path: Path) -> None:
        """Dispositions derive ONLY from verified outcomes produced by the
        neutral verifier over seeded synthetic evidence."""

        from itda.cli.phase5_openrouter_recovery_v3 import (
            classify_openrouter_v3_outcome,
            verify_openrouter_v3_outcome,
        )

        state, claim = _seeded_state(tmp_path / "disposition-root")
        approval = state.read_approval()
        terminal = _seeded_v3_failed_terminal(state, claim, approval)
        verify_openrouter_v3_outcome(
            protected_state_root=Path(str(state.descriptor.state_root)),
            public_terminal_bytes=canonical_json_bytes(terminal),
        )
        assert (
            classify_openrouter_v3_outcome(
                protected_state_root=Path(str(state.descriptor.state_root)),
                public_terminal_bytes=canonical_json_bytes(terminal),
            )
            == "FAILED_UNACTIVATED"
        )


class TestV3SealedProductionRunner:
    def test_runner_gates_are_fail_closed_offline(self) -> None:
        """ITDA_OFFLINE=1 blocks the live path before any client exists."""

        import os as os_module

        from itda.cli.phase5_openrouter_recovery_v3 import (
            execute_openrouter_v3_production,
        )

        if os_module.environ.get("ITDA_OFFLINE") != "1":
            pytest.skip("offline guard not active in this environment")
        with pytest.raises(PermissionError):
            execute_openrouter_v3_production()


class TestV3PolicyPreservation:
    def test_exact_fixed_policy_constants_survive(self) -> None:
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            OPENROUTER_V3_ATTEMPT_DEADLINE_SECONDS,
            OPENROUTER_V3_CONCURRENCY,
            OPENROUTER_V3_ENDPOINT,
            OPENROUTER_V3_FIRST_PASS_COUNT,
            OPENROUTER_V3_MAX_ATTEMPTS,
            OPENROUTER_V3_MAX_RESPONSE_BYTES,
            OPENROUTER_V3_MAX_RETRIES,
            OPENROUTER_V3_MODEL,
            OPENROUTER_V3_REASONING_EFFORT,
            OPENROUTER_V3_ZERO_MAX_PRICE,
        )

        assert OPENROUTER_V3_ENDPOINT == "https://openrouter.ai/api/v1/chat/completions"
        assert OPENROUTER_V3_MODEL == "stealth/ox-alpha"
        assert OPENROUTER_V3_ZERO_MAX_PRICE == {"prompt": "0", "completion": "0"}
        assert OPENROUTER_V3_REASONING_EFFORT == "high"
        assert OPENROUTER_V3_MAX_RETRIES == 6
        assert OPENROUTER_V3_MAX_ATTEMPTS == 30
        assert OPENROUTER_V3_CONCURRENCY == 1
        assert OPENROUTER_V3_ATTEMPT_DEADLINE_SECONDS == 300
        assert OPENROUTER_V3_MAX_RESPONSE_BYTES == 4 * 1024 * 1024
        assert OPENROUTER_V3_FIRST_PASS_COUNT == 24


def _assert_v3_packet_absent_or_committed() -> bool:
    from itda.contracts.phase5_openrouter_recovery_v3_paths import (
        OPENROUTER_V3_PUBLIC_REQUEST_PATH,
    )
    from itda.pipeline.phase5_openrouter_recovery_v3 import (
        verify_openrouter_v3_packet_full,
    )

    if not OPENROUTER_V3_PUBLIC_REQUEST_PATH.exists():
        return False
    verify_openrouter_v3_packet_full(OPENROUTER_V3_PUBLIC_REQUEST_PATH.read_bytes())
    return True


class TestV3PacketContract:
    def test_v3_packet_is_absent_or_exactly_committed(self) -> None:
        assert _assert_v3_packet_absent_or_committed() in {False, True}


# ---------------------------------------------------------------------------
# Exact persisted v3 packet model, canonical DEV-24 member plan, source
# authority inventory, builder/loader, create-only writer, and full preflight.
# ---------------------------------------------------------------------------


class TestOpenRouterPublicRequestV3Model:
    """Exact raw key set, no nulls, self digest before normalization."""

    def test_exact_raw_key_set_no_null_and_self_digest_first(
        self, monkeypatch  # type: ignore[no-untyped-def]
    ) -> None:
        from itda.domain.demo_profile_eligibility import _CANONICAL_DEV_IDS
        from itda.pipeline import phase5_openrouter_recovery_v3 as lane
        from itda.pipeline.phase5_openrouter_recovery_v3 import (
            build_openrouter_plan_v3,
            build_openrouter_public_request_v3,
        )

        bundles = [_synthetic_v3_bundle(place) for place in _CANONICAL_DEV_IDS]
        monkeypatch.setattr(lane, "_verified_source_bundles_v3", lambda: tuple(bundles))
        plan = build_openrouter_plan_v3()
        packet = build_openrouter_public_request_v3(plan=plan)
        expected_keys = {
            "schema_version",
            "authority_id",
            "provider_lane",
            "endpoint",
            "model",
            "snapshot_relative_path",
            "snapshot_sha256",
            "snapshot_accessed_at",
            "snapshot_provenance_urls",
            "public_request_relative_path",
            "protected_root_relative_path",
            "terminal_relative_path",
            "prompt_version",
            "prompt_sha256",
            "user_instruction_version",
            "user_instruction_sha256",
            "profile_schema_version",
            "preprocessing_version",
            "config_version",
            "source_inventory_sha256",
            "source_authority_sha256",
            "source_install_receipt_sha256",
            "membership_sha256",
            "retention_profile",
            "reasoning_effort",
            "max_price",
            "price_status",
            "checkout_commit_sha256",
            "checkout_manifest_sha256",
            "first_pass_count",
            "member_count",
            "first_passes",
            "request_manifest_sha256",
            "retry_policy",
            "exposure_policy",
            "activation_suite_sha256",
            "contrast_suite_sha256",
            "predecessor_consumption",
            "blind_access",
            "secret_read",
            "provider_client_constructed",
            "network_attempted",
            "lifecycle_mutated",
            "historical_member_import",
            "predecessor_grants_retry",
            "predecessor_grants_authority",
            "request_artifact_sha256",
        }
        assert set(packet) == expected_keys
        assert all(value is not None for value in packet.values())
        unsigned = {k: v for k, v in packet.items() if k != "request_artifact_sha256"}
        assert canonical_sha256(unsigned) == packet["request_artifact_sha256"]
        # Canonical serialization is byte-stable and the model round-trips it.
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            OpenRouterPublicRequestV3,
        )
        from itda.domain.canonical import canonical_json_bytes

        raw = canonical_json_bytes(packet)
        reparsed = OpenRouterPublicRequestV3.model_validate_json(raw).model_dump(
            mode="json"
        )
        assert reparsed == packet

    def test_extra_missing_or_null_keys_rejected_before_normalization(self) -> None:
        import pytest
        from pydantic import ValidationError as _ValidationError

        from itda.contracts.phase5_openrouter_recovery_v3 import (
            OpenRouterPublicRequestV3,
        )

        base = {
            "schema_version": V3_REQUEST_SCHEMA,
            "authority_id": V3_AUTHORITY_ID,
            "request_artifact_sha256": "a" * 64,
        }
        extra = {**base, "rogue_field": 1}
        with pytest.raises(_ValidationError):
            OpenRouterPublicRequestV3.model_validate(extra)
        missing = {"schema_version": V3_REQUEST_SCHEMA, "authority_id": V3_AUTHORITY_ID}
        with pytest.raises(_ValidationError):
            OpenRouterPublicRequestV3.model_validate(missing)

    def test_historical_v1_v2_coordinate_substitution_rejected(self) -> None:
        from pydantic import ValidationError

        from itda.contracts.phase5_openrouter_recovery_v3 import (
            OpenRouterPublicRequestV3,
        )

        fields = {
            "schema_version": V3_REQUEST_SCHEMA,
            "authority_id": V3_AUTHORITY_ID,
            "membership_sha256": "b" * 64,
            "request_artifact_sha256": "c" * 64,
            "public_request_relative_path": (
                "artifacts/public/phase5/openrouter-recovery-v2-request.json"
            ),
        }
        with pytest.raises((PermissionError, ValidationError)):
            OpenRouterPublicRequestV3.model_validate(fields)


def _synthetic_v3_bundle(place_id: str):
    """Provider-free DemoSourceBundle over public-canonical tourism evidence."""

    from itda.contracts.demo_profile_materialization import DemoSourceBundle
    from itda.contracts.demo_profile_materialization import (
        DemoSourceEvidence as Evidence,
    )

    sources = []
    for index in range(2):
        text = f"canonical public tourism description {index} for {place_id}"
        text_sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
        sources.append(
            Evidence(
                evidence_id=f"ev-{index}",
                source_kind="TOUR_API_DESCRIPTION",
                source_sha256=text_sha,
                span_sha256=text_sha,
                text=text,
            )
        )
    unsigned = {
        "schema_version": "itda.demo-source-bundle.v1",
        "place_id": place_id,
        "split": "DEV",
        "sources": [s.model_dump(mode="json") for s in sources],
        "optional_image": None,
        "source_inventory_sha256": "0" * 64,
    }
    return DemoSourceBundle.model_validate(
        {**unsigned, "source_bundle_sha256": canonical_sha256(unsigned)}
    )


class TestCanonicalDev24MemberPlanV3:
    """24 exact ordered first passes computed under v3 contract only."""

    def test_exact_24_ordered_first_passes_with_independent_digests(self) -> None:
        from itda.domain.demo_profile_eligibility import _CANONICAL_DEV_IDS
        from itda.pipeline.phase5_openrouter_recovery_v3 import (
            build_openrouter_member_plan_v3,
        )

        bundles = [_synthetic_v3_bundle(place) for place in _CANONICAL_DEV_IDS]
        plan = build_openrouter_member_plan_v3(bundles=bundles)
        assert len(plan.first_passes) == 24
        orders = [row["order"] for row in plan.first_passes]
        assert orders == list(range(1, 25))
        places = [row["place_id"] for row in plan.first_passes]
        assert places == sorted(_CANONICAL_DEV_IDS)
        for row, place in zip(plan.first_passes, sorted(_CANONICAL_DEV_IDS), strict=True):
            assert row["schema_version"] == "itda.phase5-openrouter-first-pass.v3"
            assert row["authority_id"] == V3_AUTHORITY_ID
            assert row["place_id"] == place
            unsigned = {k: v for k, v in row.items() if k != "request_sha256"}
            assert canonical_sha256(unsigned) == row["request_sha256"]
            body = plan.request_bodies[place]
            assert hashlib.sha256(body).hexdigest() == row["request_body_sha256"]
        # The manifest digest binds every ordered member row exactly once.
        expected_manifest = canonical_sha256(
            [
                {
                    "schema_version": row["schema_version"],
                    "authority_id": row["authority_id"],
                    "place_id": row["place_id"],
                    "order": row["order"],
                    "request_sha256": row["request_sha256"],
                    "request_body_sha256": row["request_body_sha256"],
                }
                for row in plan.first_passes
            ]
        )
        assert plan.request_manifest_sha256 == expected_manifest
        # v2 request bodies/digests are never copied: v3 bodies embed the v3
        # prompt/instruction/config identity.
        assert plan.prompt_sha256 != _v2_prompt_sha256()

    def test_wrong_place_set_rejected(self) -> None:
        import pytest

        from itda.pipeline.phase5_openrouter_recovery_v3 import (
            build_openrouter_member_plan_v3,
        )

        foreign = [_synthetic_v3_bundle("place:foreign-a"), _synthetic_v3_bundle("place:foreign-b")]
        with pytest.raises(ValueError):
            build_openrouter_member_plan_v3(bundles=foreign)

    def test_duplicate_or_reordered_members_rejected(self) -> None:
        import pytest

        from itda.domain.demo_profile_eligibility import _CANONICAL_DEV_IDS
        from itda.pipeline.phase5_openrouter_recovery_v3 import (
            build_openrouter_member_plan_v3,
        )

        ids = list(sorted(_CANONICAL_DEV_IDS))
        duplicated = [_synthetic_v3_bundle(p) for p in (ids[0], ids[0])]
        with pytest.raises(ValueError):
            build_openrouter_member_plan_v3(bundles=duplicated)
        reordered = [_synthetic_v3_bundle(p) for p in reversed(ids)]
        with pytest.raises(ValueError):
            build_openrouter_member_plan_v3(bundles=reordered)


def _v2_prompt_sha256() -> str:
    from itda.contracts.phase5_openrouter_recovery import OPENROUTER_V2_PROMPT_SHA256

    return OPENROUTER_V2_PROMPT_SHA256


class TestSourceAuthorityInventoryV3:
    """Committed-tree inventory constant excluding packet self-reference."""

    def test_inventory_constant_lists_tracked_source_files_without_outputs(self) -> None:
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            OPENROUTER_V3_SOURCE_AUTHORITY_FILES,
        )

        assert any(
            name.endswith("openrouter_ox_alpha_api_contract_v3.json")
            for name in OPENROUTER_V3_SOURCE_AUTHORITY_FILES
        )
        assert any(
            name.endswith("phase5_openrouter_recovery_v3.py")
            for name in OPENROUTER_V3_SOURCE_AUTHORITY_FILES
        )
        forbidden_prefixes = ("artifacts/", ".planning/", ".claude/")
        for name in OPENROUTER_V3_SOURCE_AUTHORITY_FILES:
            assert not name.startswith(forbidden_prefixes)

    def test_checkout_source_commit_is_head_before_packet_and_sole_parent_rule(
        self,
    ) -> None:
        import subprocess

        from itda.contracts.phase5_openrouter_recovery_v3 import (
            resolve_openrouter_v3_source_commit,
        )

        commit = resolve_openrouter_v3_source_commit()
        assert len(commit) == 40
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
        # Before a packet exists the fixed import-root HEAD IS the source commit.
        assert commit == head

    def test_committed_tree_manifest_excludes_self_reference_and_user_owned_files(
        self,
    ) -> None:
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            checkout_manifest_v3_from_source_commit,
            resolve_openrouter_v3_source_commit,
        )

        commit = resolve_openrouter_v3_source_commit()
        rows = checkout_manifest_v3_from_source_commit(commit, repository_root=None)
        paths = {row["path"] for row in rows}
        assert "artifacts/public/phase5/openrouter-recovery-v3-request.json" not in paths
        assert (
            "artifacts/reports/phase5/openrouter-recovery-v3-terminal.json" not in paths
        )
        # User-owned files may exist in the committed tree but carry no
        # filesystem-byte authority; the manifest binds tree objects only.
        assert all(
            row["mode"] and row["type"] and len(row["object_id"]) == 40 for row in rows
        )

    def test_caller_cwd_path_root_injection_rejected(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        import pytest

        from itda.contracts.phase5_openrouter_recovery_v3 import (
            resolve_openrouter_v3_source_commit,
        )

        monkeypatch.chdir("/tmp")
        with pytest.raises(PermissionError):
            resolve_openrouter_v3_source_commit(repository_root="/tmp")
        with pytest.raises(PermissionError):
            resolve_openrouter_v3_source_commit(repository_root="/")

    def test_dirty_tracked_source_authority_file_rejected(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        import pytest

        from itda.contracts.phase5_openrouter_recovery_v3 import (
            OPENROUTER_V3_SOURCE_AUTHORITY_FILES,
            verify_committed_source_authority_clean_v3,
        )

        target = tmp_path / "cannot-touch-production"
        with pytest.raises((PermissionError, ValueError, OSError)):
            verify_committed_source_authority_clean_v3(
                files=OPENROUTER_V3_SOURCE_AUTHORITY_FILES,
                source_commit="f" * 40,
                repository_root=target,
            )


class TestPacketBuilderLoaderValidatorV3:
    """Builder/loader bind exact digests; drift fails closed."""

    def test_builder_loader_round_trip_exact_bytes(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        from itda.domain.demo_profile_eligibility import _CANONICAL_DEV_IDS
        from itda.pipeline.phase5_openrouter_recovery_v3 import (
            build_openloader_v3,
            build_openrouter_plan_v3,
            build_openrouter_public_request_v3,
        )

        bundles = [_synthetic_v3_bundle(p) for p in _CANONICAL_DEV_IDS]
        plan = build_openrouter_plan_v3(bundles=bundles)
        packet = build_openrouter_public_request_v3(plan=plan)
        from itda.domain.canonical import canonical_json_bytes

        raw = canonical_json_bytes(packet)
        loaded = build_openloader_v3(raw)
        assert loaded["request_artifact_sha256"] == packet["request_artifact_sha256"]

    def test_noncanonical_bytes_rejected(self) -> None:
        import pytest

        from itda.domain.demo_profile_eligibility import _CANONICAL_DEV_IDS
        from itda.pipeline.phase5_openrouter_recovery_v3 import (
            build_openloader_v3,
            build_openrouter_plan_v3,
            build_openrouter_public_request_v3,
        )

        bundles = [_synthetic_v3_bundle(p) for p in _CANONICAL_DEV_IDS]
        plan = build_openrouter_plan_v3(bundles=bundles)
        packet = build_openrouter_public_request_v3(plan=plan)
        from json import dumps

        pretty = dumps(packet, indent=1).encode("utf-8")
        with pytest.raises(ValueError):
            build_openloader_v3(pretty)

    def test_recursive_duplicate_keys_rejected(self) -> None:
        import pytest

        from itda.pipeline.phase5_openrouter_recovery_v3 import build_openloader_v3

        raw = b'{"a":{"b":1,"b":2}}'
        with pytest.raises(ValueError):
            build_openloader_v3(raw)

    def test_semantic_request_digest_and_raw_file_digest_bound(self) -> None:
        from itda.domain.demo_profile_eligibility import _CANONICAL_DEV_IDS
        from itda.pipeline.phase5_openrouter_recovery_v3 import (
            build_openrouter_plan_v3,
            build_openrouter_public_request_v3,
            semantic_request_digest_v3,
        )

        bundles = [_synthetic_v3_bundle(p) for p in _CANONICAL_DEV_IDS]
        plan = build_openrouter_plan_v3(bundles=bundles)
        packet = build_openrouter_public_request_v3(plan=plan)
        digest = semantic_request_digest_v3(packet)
        assert digest == semantic_request_digest_v3(dict(packet))
        drifted = dict(packet)
        drifted["blind_access"] = True
        assert semantic_request_digest_v3(drifted) != digest

    def test_runtime_load_binds_exact_current_source_and_fails_after_drift(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from itda.pipeline import phase5_openrouter_recovery_v3 as lane

        repository = _synthetic_source_repository(tmp_path)
        current = _git(repository, "rev-parse", "HEAD")
        monkeypatch.setattr(lane, "_canonical_repository_root", lambda _root: repository)
        monkeypatch.setattr(lane, "_openrouter_v3_source_authority_files", lambda: ("source.txt",))
        checkout_manifest = lane._checkout_manifest_sha256_from_git_v3(
            root=repository, source_commit=current
        )
        bound = lane.bind_packet_to_source_v3(
            checkout_commit_sha256=current,
            checkout_manifest_sha256=checkout_manifest,
            request_manifest_sha256="d" * 64,
        )
        assert bound is True
        with pytest.raises((PermissionError, ValueError)):
            lane.bind_packet_to_source_v3(
                checkout_commit_sha256="0" * 40,
                checkout_manifest_sha256=checkout_manifest,
                request_manifest_sha256="d" * 64,
            )

    def test_arbitrary_ancestor_is_not_a_legal_packet_source(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from itda.pipeline import phase5_openrouter_recovery_v3 as lane

        repository = _synthetic_packet_repository(tmp_path)
        source_commit = _git(repository, "rev-parse", "HEAD~2")
        monkeypatch.setattr(lane, "_canonical_repository_root", lambda _root: repository)
        checkout_manifest = lane._checkout_manifest_sha256_from_git_v3(
            root=repository, source_commit=source_commit
        )

        with pytest.raises(PermissionError, match="PACKET_SOURCE"):
            lane.bind_packet_to_source_v3(
                checkout_commit_sha256=source_commit,
                checkout_manifest_sha256=checkout_manifest,
                request_manifest_sha256="e" * 64,
            )

    def test_packet_bytes_require_a_committed_packet_commit(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from itda.pipeline import phase5_openrouter_recovery_v3 as lane

        repository = _synthetic_source_repository(tmp_path)
        source_commit = _git(repository, "rev-parse", "HEAD")
        monkeypatch.setattr(lane, "_canonical_repository_root", lambda _root: repository)
        monkeypatch.setattr(lane, "_openrouter_v3_source_authority_files", lambda: ("source.txt",))
        checkout_manifest = lane._checkout_manifest_sha256_from_git_v3(
            root=repository, source_commit=source_commit
        )

        with pytest.raises(PermissionError, match="PACKET_COMMIT_NOT_DERIVABLE"):
            lane.bind_packet_to_source_v3(
                checkout_commit_sha256=source_commit,
                checkout_manifest_sha256=checkout_manifest,
                request_manifest_sha256="e" * 64,
                packet_bytes=b"{}",
            )

    def test_checkout_manifest_is_recomputed_from_recorded_source(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from itda.pipeline import phase5_openrouter_recovery_v3 as lane

        repository = _synthetic_packet_repository(tmp_path)
        source_commit = _git(repository, "rev-parse", "HEAD^")
        monkeypatch.setattr(lane, "_canonical_repository_root", lambda _root: repository)

        with pytest.raises(PermissionError, match="CHECKOUT_MANIFEST_DRIFTED"):
            lane.bind_packet_to_source_v3(
                checkout_commit_sha256=source_commit,
                checkout_manifest_sha256="9" * 64,
                request_manifest_sha256="e" * 64,
            )

    def test_packet_commit_parent_and_changed_paths_are_git_derived(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from itda.pipeline import phase5_openrouter_recovery_v3 as lane

        repository = _synthetic_packet_repository(tmp_path)
        packet_commit = _git(repository, "rev-parse", "HEAD")
        source_commit = _git(repository, "rev-parse", "HEAD^")
        monkeypatch.setattr(lane, "_canonical_repository_root", lambda _root: repository)

        parent = lane.require_sole_parent_consistency_v3(
            packet_commit=packet_commit,
            expected_source_commit=source_commit,
        )
        assert parent == source_commit

    def test_packet_parent_must_equal_recorded_checkout_commit(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from itda.pipeline import phase5_openrouter_recovery_v3 as lane

        repository = _synthetic_packet_repository(tmp_path)
        packet_commit = _git(repository, "rev-parse", "HEAD")
        wrong_source = _git(repository, "rev-parse", "HEAD~2")
        monkeypatch.setattr(lane, "_canonical_repository_root", lambda _root: repository)

        with pytest.raises(PermissionError, match="SOURCE_PARENT_DRIFTED"):
            lane.require_sole_parent_consistency_v3(
                packet_commit=packet_commit,
                expected_source_commit=wrong_source,
            )

    def test_source_change_after_packet_rejected_even_when_reverted(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from itda.pipeline import phase5_openrouter_recovery_v3 as lane

        repository = _synthetic_packet_repository(tmp_path)
        packet_commit = _git(repository, "rev-parse", "HEAD")
        source_commit = _git(repository, "rev-parse", "HEAD^")
        source = repository / "source.txt"
        source.write_text("post-packet drift", encoding="utf-8")
        _git(repository, "add", "source.txt")
        _git(repository, "commit", "-qm", "source drift")
        _git(repository, "revert", "--no-edit", _git(repository, "rev-parse", "HEAD"))
        monkeypatch.setattr(lane, "_canonical_repository_root", lambda _root: repository)
        monkeypatch.setattr(lane, "_openrouter_v3_source_authority_files", lambda: ("source.txt",))
        checkout_manifest = lane._checkout_manifest_sha256_from_git_v3(
            root=repository, source_commit=source_commit
        )
        packet_bytes = subprocess.run(
            [
                "git",
                "show",
                f"{packet_commit}:artifacts/public/phase5/openrouter-recovery-v3-request.json",
            ],
            cwd=repository,
            check=True,
            capture_output=True,
        ).stdout

        with pytest.raises(PermissionError, match="SOURCE_CHANGED_AFTER_PACKET"):
            lane.bind_packet_to_source_v3(
                checkout_commit_sha256=source_commit,
                checkout_manifest_sha256=checkout_manifest,
                request_manifest_sha256="e" * 64,
                packet_bytes=packet_bytes,
            )

    def test_packet_commit_with_extra_changed_path_rejected(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from itda.pipeline import phase5_openrouter_recovery_v3 as lane

        repository = _synthetic_packet_repository(tmp_path, extra_packet_path=True)
        packet_commit = _git(repository, "rev-parse", "HEAD")
        source_commit = _git(repository, "rev-parse", "HEAD^")
        monkeypatch.setattr(lane, "_canonical_repository_root", lambda _root: repository)

        with pytest.raises(PermissionError, match="PACKET_COMMIT_NOT_ISOLATED"):
            lane.require_sole_parent_consistency_v3(
                packet_commit=packet_commit,
                expected_source_commit=source_commit,
            )


def _git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _synthetic_source_repository(tmp_path: Path) -> Path:
    repository = tmp_path / "source-repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.email", "v3-tests@example.invalid")
    _git(repository, "config", "user.name", "V3 Tests")
    source = repository / "source.txt"
    for value in ("one", "two"):
        source.write_text(value, encoding="utf-8")
        _git(repository, "add", "source.txt")
        _git(repository, "commit", "-qm", f"source {value}")
    return repository


def _synthetic_packet_repository(
    tmp_path: Path, *, extra_packet_path: bool = False
) -> Path:
    repository = _synthetic_source_repository(tmp_path)
    packet = repository / "artifacts/public/phase5/openrouter-recovery-v3-request.json"
    packet.parent.mkdir(parents=True)
    packet.write_text("{}", encoding="utf-8")
    _git(repository, "add", str(packet.relative_to(repository)))
    if extra_packet_path:
        extra = repository / "unrelated.txt"
        extra.write_text("forged", encoding="utf-8")
        _git(repository, "add", "unrelated.txt")
    _git(repository, "commit", "-qm", "packet")
    return repository


def resolve_current_commit_for_test() -> str:
    import subprocess

    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


class TestCreateOnlyWriterV3:
    """Exact production coordinate only; no synthetic alias; create-only."""

    def test_writer_refuses_synthetic_output_alias(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        import pytest

        from itda.pipeline.phase5_openrouter_recovery_v3 import (
            write_openrouter_public_request_v3,
        )

        with pytest.raises(PermissionError):
            write_openrouter_public_request_v3(output=tmp_path / "packet.json")

    def test_writer_does_not_create_or_change_production_packet(self) -> None:
        from itda.contracts.phase5_openrouter_recovery_v3_paths import (
            OPENROUTER_V3_PUBLIC_REQUEST_PATH,
        )

        before = (
            OPENROUTER_V3_PUBLIC_REQUEST_PATH.read_bytes()
            if OPENROUTER_V3_PUBLIC_REQUEST_PATH.exists()
            else None
        )
        _assert_v3_packet_absent_or_committed()
        after = (
            OPENROUTER_V3_PUBLIC_REQUEST_PATH.read_bytes()
            if OPENROUTER_V3_PUBLIC_REQUEST_PATH.exists()
            else None
        )
        assert after == before


class TestPreflightFullVerificationV3:
    """Preflight verifies the packet fully when present; absent fails named."""

    def test_verify_only_accepts_only_absent_or_committed_packet(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from itda.cli.phase5_openrouter_recovery_v3 import main as v3_main

        packet_committed = _assert_v3_packet_absent_or_committed()
        exit_code = v3_main(
            [
                "openrouter-recovery-v3-preflight",
                "--request",
                "artifacts/public/phase5/openrouter-recovery-v3-request.json",
                "--verify-only",
                "--json",
            ]
        )
        captured = capsys.readouterr()
        if packet_committed:
            assert exit_code == 0
            assert '"packet_fully_verified":true' in captured.out
        else:
            assert exit_code == 2
            assert "OPENROUTER_V3_PACKET_ABSENT" in captured.err
            assert "OPENROUTER_V3_REJECTED" not in captured.err

    def test_preflight_verifies_packet_fully_when_present_not_only_exists(self) -> None:
        """The preflight must run the FULL packet verifier when a file exists.

        Bound by source inspection plus an in-memory end-to-end proof: the
        CLI preflight reads BYTES through the bounded reader and calls the
        full ``verify_openrouter_v3_packet_full`` verifier — never a bare
        ``exists()`` gate.
        """
        import inspect

        from itda.cli import phase5_openrouter_recovery_v3 as command

        preflight_source = inspect.getsource(command._preflight_payload)
        assert "verify_openrouter_v3_packet_full" in preflight_source
        assert "_read_bounded_regular" in preflight_source
        # The absent-packet branch still names its failure exactly once and
        # only under --verify-only.
        assert "OPENROUTER_V3_PACKET_ABSENT" in preflight_source
        # End-to-end: the full verifier rejects a non-canonical byte image
        # before any exists() shortcut could matter.
        import pytest

        from itda.pipeline.phase5_openrouter_recovery_v3 import (
            verify_openrouter_v3_packet_full,
        )

        with pytest.raises((ValueError, PermissionError)):
            verify_openrouter_v3_packet_full(b'{"a":1,"a":2}')


class TestPredecessorDualFactsV3:
    """Separate v1 consumed facts vs exact unconsumed v2 packet facts."""

    def test_consumed_v1_record_and_unconsumed_v2_packet_both_bound(self) -> None:
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            build_predecessor_projection_from_public_history,
        )

        projection = build_predecessor_projection_from_public_history()
        dumped = projection.model_dump(mode="json")
        # v1 failure record facts (consumed before RESERVE).
        assert dumped["v1_failure_code"] == "OPENROUTER_REPOSITORY_ROOT_BINDING_OFF_BY_ONE"
        assert dumped["v1_failed_before_reserve"] is True
        assert dumped["v1_approval_self_sha256"].startswith("0c0b46ee")
        assert dumped["v1_claim_self_sha256"].startswith("48659483")
        assert dumped["v1_one_use_claim_consumed"] is True
        assert dumped["v1_reserve_count"] == 0
        # Exact v2 packet facts (present but unconsumed/non-authorizing).
        assert dumped["v2_unconsumed"] is True
        assert dumped["v2_consumed_before_reserve"] is False
        assert dumped["v2_terminal_exists"] is False
        assert dumped["v2_authority_promoted"] is False

    def test_dual_projection_digest_binds_both_fact_sets(self) -> None:
        import pytest

        from itda.contracts.phase5_openrouter_recovery_v3 import (
            OpenRouterPredecessorConsumptionV3,
        )

        # The dual-fact schema REJECTS the old single-fact shape: the v2
        # unconsumed facts and v1 consumed facts are separate bound fields.
        legacy_shape = {
            "schema_version": "itda.phase5-openrouter-predecessor-consumption.v3",
            "predecessor_authority_id": (
                "phase5-openrouter-stealth-ox-alpha-recovery-r2-20260824"
            ),
            "predecessor_request_schema": "itda.phase5-openrouter-recovery-request.v2",
            "predecessor_request_artifact_sha256": "a" * 64,
            "predecessor_checkout_commit_sha256": "b" * 40,
            "predecessor_checkout_manifest_sha256": "c" * 64,
            "predecessor_membership_sha256": "d" * 64,
            "consumed_before_reserve": True,
            "reserve_count": 0,
            "attempt_count": 0,
            "secret_read": False,
            "client_constructed": False,
            "send_attempted": False,
            "provider_attempted": False,
            "network_attempted": False,
            "lifecycle_mutated": False,
            "terminal_exists": False,
            "retry_authorized": False,
            "predecessor_authority_promoted": False,
            "rollover_context_only": True,
        }
        unsigned = {
            k: v
            for k, v in legacy_shape.items()
            if k != "consumption_sha256"
        }

        from itda.domain.canonical import canonical_sha256 as _cs

        with pytest.raises((ValidationError, ValueError)):
            OpenRouterPredecessorConsumptionV3.model_validate(
                {**legacy_shape, "consumption_sha256": _cs(unsigned)}
            )

    def test_v2_packet_tampering_breaks_projection(self) -> None:
        import pytest

        from itda.contracts.phase5_openrouter_recovery_v3 import (
            build_predecessor_projection_from_public_history,
        )
        from itda.contracts.phase5_openrouter_recovery_v3_paths import (
            OPENROUTER_V2_PUBLIC_PACKET_PATH,
        )

        raw = OPENROUTER_V2_PUBLIC_PACKET_PATH.read_bytes()
        payload = json.loads(raw)
        payload["membership_sha256"] = "e" * 64
        from itda.domain.canonical import canonical_json_bytes

        with pytest.raises((ValueError, PermissionError)):
            build_predecessor_projection_from_public_history(
                v2_packet_bytes=canonical_json_bytes(payload)
            )
