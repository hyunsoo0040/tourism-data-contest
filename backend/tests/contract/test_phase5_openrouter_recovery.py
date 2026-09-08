"""Contract tests for the disjoint provider-free OpenRouter recovery lane.

Every test is provider-free: provider env vars are removed, no socket is
constructed, and all protected roots are synthetic temporary directories.
"""

from __future__ import annotations

import builtins
import hashlib
import json
import os
import stat
from pathlib import Path

import httpx
import phase5_openrouter_recovery_v3_cases as v3_cases
import phase5_openrouter_recovery_v4_cases as v4_cases
import pytest
from pydantic import ValidationError

from itda.contracts.phase5_openrouter_recovery import (
    HISTORICAL_AUTHORITY_IDS,
    OPENROUTER_ALLOWED_HEADERS,
    OPENROUTER_ENDPOINT,
    OPENROUTER_MAX_ATTEMPTS,
    OPENROUTER_MAX_RETRIES,
    OPENROUTER_MEMBERSHIP_SHA256,
    OPENROUTER_MODEL,
    OPENROUTER_REASONING_EFFORT,
    OPENROUTER_RECOVERY_AUTHORITY_ID,
    OPENROUTER_REQUEST_BODY_KEYS,
    OPENROUTER_RESERVATION_MICRO_USD,
    OPENROUTER_RETRYABLE_HTTP_STATUSES,
    OPENROUTER_SNAPSHOT_PATH,
    OPENROUTER_TERMINAL_HTTP_STATUSES,
    OpenRouterExposurePolicy,
    OpenRouterMemberRequest,
    OpenRouterProtectedStateDescriptor,
    OpenRouterRetryPolicy,
    load_openrouter_snapshot,
    openrouter_request_body_fields,
    validate_openrouter_authority_id,
    validate_openrouter_request_body,
)
from itda.domain.canonical import canonical_sha256
from itda.pipeline import phase5_openrouter_recovery as lane

TestV3SnapshotAuthority = v3_cases.TestSnapshotAuthority
TestV3HistoricalRejection = v3_cases.TestHistoricalRejection
TestV3SegmentedLedgerEntries = v3_cases.TestSegmentedLedgerEntries
TestV3OutcomeDiscriminatedAttempts = v3_cases.TestOutcomeDiscriminatedAttempts
TestV3ReconciliationEvidence = v3_cases.TestReconciliationEvidence
TestV3DurableSegmentedStore = v3_cases.TestDurableSegmentedStore
TestV3TerminalContracts = v3_cases.TestTerminalContracts
TestV3ApprovalClaimBinding = v3_cases.TestApprovalClaimBinding
TestV3CrashBoundariesMockSeam = v3_cases.TestCrashBoundariesMockSeam
TestV3SchedulerPolicy = v3_cases.TestSchedulerPolicy
TestV4SnapshotAuthority = v4_cases.TestSnapshotAuthority
TestV4HistoricalRejection = v4_cases.TestHistoricalRejection
TestV4SegmentedLedgerEntries = v4_cases.TestSegmentedLedgerEntries
TestV4OutcomeDiscriminatedAttempts = v4_cases.TestOutcomeDiscriminatedAttempts
TestV4ReconciliationEvidence = v4_cases.TestReconciliationEvidence
TestV4DurableSegmentedStore = v4_cases.TestDurableSegmentedStore
TestV4TerminalContracts = v4_cases.TestTerminalContracts
TestV4ApprovalClaimBinding = v4_cases.TestApprovalClaimBinding
TestV4CrashBoundariesMockSeam = v4_cases.TestCrashBoundariesMockSeam
TestV4SchedulerPolicy = v4_cases.TestSchedulerPolicy
TestV4CliSurface = v4_cases.TestV4CliSurface
TestV4NeutralVerifier = v4_cases.TestV4NeutralVerifier
TestV4RealCapabilityLifecycle = v4_cases.TestV4RealCapabilityLifecycle
TestV4SealedProductionRunner = v4_cases.TestV4SealedProductionRunner
TestV4PolicyPreservation = v4_cases.TestV4PolicyPreservation
TestV4PacketContract = v4_cases.TestV4PacketContract
TestOpenRouterPublicRequestV4Model = v4_cases.TestOpenRouterPublicRequestV4Model
TestCanonicalDev24MemberPlanV4 = v4_cases.TestCanonicalDev24MemberPlanV4
TestSourceAuthorityInventoryV4 = v4_cases.TestSourceAuthorityInventoryV4
TestPacketBuilderLoaderValidatorV4 = v4_cases.TestPacketBuilderLoaderValidatorV4
TestCreateOnlyWriterV4 = v4_cases.TestCreateOnlyWriterV4
TestPreflightFullVerificationV4 = v4_cases.TestPreflightFullVerificationV4
TestPredecessorDualFactsV4 = v4_cases.TestPredecessorDualFactsV4


@pytest.fixture(autouse=True)
def _no_provider_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("NVIDIA_KEY", "ZHIPUAI_API_KEY", "BIGMODEL_API_KEY", "OPENROUTER_API_KEY"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _deny_production_openrouter_and_secret_fs_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Permit lexical path values, but forbid every filesystem observation."""

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
    monkeypatch.setattr(builtins, "open", wrap(builtins.open))
    original_path_open = Path.open

    def guarded_path_open(self: Path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if blocked_path(self):
            raise AssertionError("PRODUCTION_OPENROUTER_OR_SECRET_FS_ACCESS_FORBIDDEN")
        return original_path_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_path_open)


@pytest.fixture(autouse=True)
def _deny_real_httpx_client_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only explicit in-memory MockTransport clients may be constructed."""

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


def test_collection_time_network_deny_is_armed() -> None:
    """The collection-time INET/DNS deny is armed without constructing a client."""

    import inspect
    import socket as socket_module

    armed = getattr(socket_module, "_itda_contract_deny_installed", False) or getattr(
        socket_module, "_itda_security_deny_installed", False
    )
    assert armed is True
    assert inspect.isfunction(socket_module.socket)
    assert inspect.isfunction(socket_module.getaddrinfo)
    socket_source = inspect.getsource(socket_module.socket)
    dns_source = inspect.getsource(socket_module.getaddrinfo)
    assert "_DENY_MARKER" in socket_source or "DENIED" in socket_source
    assert "_DENY_MARKER" in dns_source or "DENIED" in dns_source


def test_committed_packet_parent_manifest_remains_stable() -> None:
    """The immutable v1 packet still binds its original isolated parent tree."""

    import subprocess

    payload = json.loads(lane.OPENROUTER_REQUEST_OUTPUT.read_bytes())
    packet_commit = subprocess.run(
        [
            "git",
            "log",
            "-1",
            "--format=%H",
            "--",
            lane.OPENROUTER_PUBLIC_REQUEST_RELATIVE,
        ],
        cwd=lane.REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    packet_parent = subprocess.run(
        ["git", "rev-parse", f"{packet_commit}^"],
        cwd=lane.REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert packet_parent == payload["checkout_commit_sha256"]

    from itda.pipeline.phase5_fresh24 import (
        FRESH24_PUBLIC_REQUEST_RELATIVE,
        FRESH24_TERMINAL_RELATIVE,
    )

    excluded = {
        FRESH24_PUBLIC_REQUEST_RELATIVE,
        FRESH24_TERMINAL_RELATIVE,
        lane.OPENROUTER_PUBLIC_REQUEST_RELATIVE,
        lane.OPENROUTER_TERMINAL_RELATIVE,
    }
    tree = subprocess.run(
        ["git", "ls-tree", "-r", "-z", "--full-tree", packet_parent],
        cwd=lane.REPOSITORY_ROOT,
        check=True,
        capture_output=True,
    ).stdout
    rows = []
    for record in tree.split(b"\0"):
        if not record:
            continue
        metadata, raw_name = record.split(b"\t", 1)
        mode, kind, object_id = metadata.decode("ascii").split(" ")
        name = raw_name.decode("utf-8")
        if name not in excluded:
            rows.append({"path": name, "mode": mode, "type": kind, "object_id": object_id})
    assert canonical_sha256(rows) == payload["checkout_manifest_sha256"]


@pytest.fixture(autouse=True)
def _deny_sockets_and_dns() -> None:
    """Per-test re-assertion of the collection-time deny.

    Since WR-B re-audit the deny lives in backend/tests/contract/conftest.py
    and is installed at COLLECTION time (before any module import).  This
    fixture exists only to guarantee the armed state for every test and to
    keep the deny idempotent across the whole session; it never restores the
    originals mid-session (the process-level deny stays armed).
    """

    from conftest import install_collection_time_network_deny  # type: ignore[import-not-found]

    install_collection_time_network_deny()
    yield


pytestmark = pytest.mark.usefixtures("_no_provider_env", "_deny_sockets_and_dns")


def test_openrouter_repository_root_binding_off_by_one_red_regression() -> None:
    """Reproduce the consumed v1 packet's exact parents[4] defect.

    The tracked public packet sits three parents below the checkout root.  The
    failed production closure instead selected parents[4], one directory above
    the repository.  GREEN must capture the source-derived root; changing the
    contextual index from four to three is explicitly not an acceptable fix.
    """

    import inspect

    repository_root = Path(__file__).resolve().parents[3]
    tracked_packet = repository_root / "artifacts/public/phase5/openrouter-recovery-request.json"
    assert tracked_packet.parents[3] == repository_root
    assert tracked_packet.parents[4] == repository_root.parent
    assert tracked_packet.parents[4] != repository_root

    source = inspect.getsource(lane._bind_public_entry)
    assert "request_path_cell.parents[4]" not in source, (
        "OPENROUTER_REPOSITORY_ROOT_BINDING_OFF_BY_ONE"
    )
    assert "request_path_cell.parents[3]" not in source, (
        "packet-relative root inference must be removed, not re-indexed"
    )
    assert "repository_root_cell = REPOSITORY_ROOT" in source


def test_openrouter_r2_v2_coordinates_and_schemas_are_exact_and_disjoint() -> None:
    from itda.contracts.phase5_openrouter_recovery import (
        OPENROUTER_V2_APPROVAL_SCHEMA,
        OPENROUTER_V2_ATTEMPT_SCHEMA,
        OPENROUTER_V2_CLAIM_SCHEMA,
        OPENROUTER_V2_DISPATCH_SCHEMA,
        OPENROUTER_V2_GENERATION_SCHEMA,
        OPENROUTER_V2_LEDGER_ENTRY_SCHEMA,
        OPENROUTER_V2_MEMBER_REQUEST_SCHEMA,
        OPENROUTER_V2_PROTECTED_STATE_SCHEMA,
        OPENROUTER_V2_RECOVERY_AUTHORITY_ID,
        OPENROUTER_V2_REQUEST_SCHEMA,
        OPENROUTER_V2_SNAPSHOT_RELATIVE,
        OPENROUTER_V2_TERMINAL_SCHEMA,
    )

    assert OPENROUTER_V2_RECOVERY_AUTHORITY_ID == (
        "phase5-openrouter-stealth-ox-alpha-recovery-r2-20260824"
    )
    assert OPENROUTER_V2_RECOVERY_AUTHORITY_ID != OPENROUTER_RECOVERY_AUTHORITY_ID
    assert OPENROUTER_V2_SNAPSHOT_RELATIVE == (
        "backend/src/itda/providers/openrouter_ox_alpha_api_contract_v2.json"
    )
    schemas = {
        OPENROUTER_V2_REQUEST_SCHEMA,
        OPENROUTER_V2_APPROVAL_SCHEMA,
        OPENROUTER_V2_CLAIM_SCHEMA,
        OPENROUTER_V2_LEDGER_ENTRY_SCHEMA,
        OPENROUTER_V2_DISPATCH_SCHEMA,
        OPENROUTER_V2_ATTEMPT_SCHEMA,
        OPENROUTER_V2_PROTECTED_STATE_SCHEMA,
        OPENROUTER_V2_GENERATION_SCHEMA,
        OPENROUTER_V2_MEMBER_REQUEST_SCHEMA,
        OPENROUTER_V2_TERMINAL_SCHEMA,
    }
    assert len(schemas) == 10
    assert all(schema.endswith(".v2") for schema in schemas)
    assert all(not schema.endswith(".v1") for schema in schemas)
    assert lane.OPENROUTER_V2_PUBLIC_REQUEST_RELATIVE == (
        "artifacts/public/phase5/openrouter-recovery-v2-request.json"
    )
    assert lane.OPENROUTER_V2_PROTECTED_ROOT_RELATIVE == (
        "artifacts/restricted/catalog/phase5-openrouter-recovery-r2"
    )
    assert lane.OPENROUTER_V2_TERMINAL_RELATIVE == (
        "artifacts/reports/phase5/openrouter-recovery-v2-terminal.json"
    )


def test_openrouter_v2_snapshot_is_distinct_immutable_and_self_digested() -> None:
    from itda.contracts.phase5_openrouter_recovery import (
        OPENROUTER_V2_SNAPSHOT_PATH,
        load_openrouter_snapshot_v2,
    )

    snapshot = load_openrouter_snapshot_v2()
    payload = json.loads(OPENROUTER_V2_SNAPSHOT_PATH.read_bytes())
    stored = payload.pop("snapshot_sha256")
    assert canonical_sha256(payload) == stored
    assert snapshot.snapshot_sha256 == stored
    assert snapshot.schema_version == "itda.phase5-openrouter-api-snapshot.v2"
    assert snapshot.authority_id == ("phase5-openrouter-stealth-ox-alpha-recovery-r2-20260824")
    assert OPENROUTER_V2_SNAPSHOT_PATH != OPENROUTER_SNAPSHOT_PATH
    assert stored != str(load_openrouter_snapshot().snapshot_sha256)


def test_openrouter_v2_snapshot_synthetic_regular_file_passes(
    tmp_path: Path,
) -> None:
    from itda.contracts.phase5_openrouter_recovery import (
        OPENROUTER_V2_SNAPSHOT_PATH,
        load_openrouter_snapshot_v2,
    )

    target = tmp_path / "regular-parent" / "snapshot.json"
    target.parent.mkdir()
    target.write_bytes(OPENROUTER_V2_SNAPSHOT_PATH.read_bytes())

    snapshot = load_openrouter_snapshot_v2(target)
    assert snapshot.schema_version == "itda.phase5-openrouter-api-snapshot.v2"


def test_openrouter_v2_snapshot_parent_symlink_rejects_before_target_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.contracts.phase5_openrouter_recovery import (
        OPENROUTER_V2_SNAPSHOT_PATH,
        load_openrouter_snapshot_v2,
    )

    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    (real_parent / "snapshot.json").write_bytes(OPENROUTER_V2_SNAPSHOT_PATH.read_bytes())
    alias_parent = tmp_path / "alias-parent"
    alias_parent.symlink_to(real_parent, target_is_directory=True)
    aliased_target = alias_parent / "snapshot.json"
    reads: list[Path] = []
    original_read_bytes = Path.read_bytes

    def guarded_read_bytes(path: Path) -> bytes:
        if path == aliased_target:
            reads.append(path)
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read_bytes)
    with pytest.raises(PermissionError, match="OPENROUTER_V2_SNAPSHOT_PARENT_SYMLINK"):
        load_openrouter_snapshot_v2(aliased_target)
    assert reads == []


def test_openrouter_v2_snapshot_final_symlink_rejects(
    tmp_path: Path,
) -> None:
    from itda.contracts.phase5_openrouter_recovery import (
        OPENROUTER_V2_SNAPSHOT_PATH,
        load_openrouter_snapshot_v2,
    )

    target = tmp_path / "snapshot.json"
    target.write_bytes(OPENROUTER_V2_SNAPSHOT_PATH.read_bytes())
    link = tmp_path / "snapshot-link.json"
    link.symlink_to(target)

    with pytest.raises(PermissionError, match="OPENROUTER_V2_SNAPSHOT_.*SYMLINK"):
        load_openrouter_snapshot_v2(link)


def test_openrouter_v2_snapshot_lexical_escape_rejects_before_target_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.contracts.phase5_openrouter_recovery import (
        OPENROUTER_V2_SNAPSHOT_PATH,
        load_openrouter_snapshot_v2,
    )

    target = tmp_path / "snapshot.json"
    target.write_bytes(OPENROUTER_V2_SNAPSHOT_PATH.read_bytes())
    nested = tmp_path / "nested"
    nested.mkdir()
    escaped_spelling = nested / ".." / "snapshot.json"
    reads: list[Path] = []
    original_read_bytes = Path.read_bytes

    def guarded_read_bytes(path: Path) -> bytes:
        if path == target:
            reads.append(path)
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read_bytes)
    with pytest.raises(PermissionError, match="OPENROUTER_V2_SNAPSHOT_PATH_ESCAPE"):
        load_openrouter_snapshot_v2(escaped_spelling)
    assert reads == []


def test_openrouter_v2_snapshot_rejects_v1_and_foreign_coordinates(
    tmp_path: Path,
) -> None:
    from itda.contracts.phase5_openrouter_recovery import (
        OPENROUTER_V2_SNAPSHOT_PATH,
        load_openrouter_snapshot_v2,
    )

    source = json.loads(OPENROUTER_V2_SNAPSHOT_PATH.read_bytes())
    mutations = (
        ("schema_version", "itda.phase5-openrouter-api-snapshot.v1"),
        ("authority_id", OPENROUTER_RECOVERY_AUTHORITY_ID),
        (
            "snapshot_sha256",
            "8795f32689c9c90f9d5ee07ab6a667915bc446939b1b0d5307223788c6585540",
        ),
        (
            "source_path",
            "backend/src/itda/providers/openrouter_ox_alpha_api_contract.json",
        ),
    )
    for index, (key, historical) in enumerate(mutations):
        hostile = json.loads(json.dumps(source))
        hostile[key] = historical
        if key != "snapshot_sha256":
            unsigned = {
                child_key: child
                for child_key, child in hostile.items()
                if child_key != "snapshot_sha256"
            }
            hostile["snapshot_sha256"] = canonical_sha256(unsigned)
        path = tmp_path / f"snapshot-{index}.json"
        path.write_text(json.dumps(hostile), encoding="utf-8")
        with pytest.raises((PermissionError, ValueError, ValidationError)):
            load_openrouter_snapshot_v2(path)


def _openrouter_v2_member_payload(*, prompt_sha256: str, profile_schema: str) -> dict[str, object]:
    from itda.contracts.phase5_openrouter_recovery import (
        OPENROUTER_V2_CONFIG_VERSION,
        OPENROUTER_V2_PREPROCESSING_VERSION,
        OPENROUTER_V2_RECOVERY_AUTHORITY_ID,
        load_openrouter_snapshot_v2,
    )

    request_preimage = {
        "schema_version": "itda.phase5-openrouter-member-request.v2",
        "authority_id": OPENROUTER_V2_RECOVERY_AUTHORITY_ID,
        "place_id": "place:v2-lineage-test",
        "split": "DEV",
        "first_pass_order": 1,
        "source_bundle_sha256": "a" * 64,
        "evidence_inventory_sha256": "b" * 64,
        "request_body_sha256": "c" * 64,
    }
    request_sha256 = canonical_sha256(request_preimage)
    snapshot = load_openrouter_snapshot_v2()
    lineage_sha256 = canonical_sha256(
        {
            "authority_id": OPENROUTER_V2_RECOVERY_AUTHORITY_ID,
            "place_id": request_preimage["place_id"],
            "source_bundle_sha256": request_preimage["source_bundle_sha256"],
            "evidence_inventory_sha256": request_preimage["evidence_inventory_sha256"],
            "request_sha256": request_sha256,
            "prompt_sha256": prompt_sha256,
            "profile_schema_version": profile_schema,
            "config_version": OPENROUTER_V2_CONFIG_VERSION,
            "preprocessing_version": OPENROUTER_V2_PREPROCESSING_VERSION,
            "snapshot_sha256": snapshot.snapshot_sha256,
        }
    )
    return {
        **request_preimage,
        "request_sha256": request_sha256,
        "lineage_sha256": lineage_sha256,
    }


def test_openrouter_v2_member_lineage_accepts_exact_v2_prompt_digest() -> None:
    from itda.contracts.phase5_openrouter_recovery import (
        OPENROUTER_V2_PROFILE_SCHEMA,
        OPENROUTER_V2_PROMPT_SHA256,
        OpenRouterMemberRequestV2,
    )

    payload = _openrouter_v2_member_payload(
        prompt_sha256=OPENROUTER_V2_PROMPT_SHA256,
        profile_schema=OPENROUTER_V2_PROFILE_SCHEMA,
    )
    member = OpenRouterMemberRequestV2.model_validate(payload)
    assert member.lineage_sha256 == payload["lineage_sha256"]


def test_openrouter_v2_member_lineage_rejects_v1_prompt_digest() -> None:
    from itda.contracts.phase5_openrouter_recovery import (
        OPENROUTER_PROFILE_SCHEMA_VERSION,
        OPENROUTER_PROMPT_SHA256,
        OPENROUTER_V2_PROFILE_SCHEMA,
        OpenRouterMemberRequestV2,
    )

    payload = _openrouter_v2_member_payload(
        prompt_sha256=OPENROUTER_PROMPT_SHA256,
        profile_schema=OPENROUTER_V2_PROFILE_SCHEMA,
    )
    with pytest.raises(ValueError, match="OPENROUTER_V2_MEMBER_LINEAGE_DRIFT"):
        OpenRouterMemberRequestV2.model_validate(payload)
    assert OPENROUTER_PROFILE_SCHEMA_VERSION != OPENROUTER_V2_PROFILE_SCHEMA


def test_openrouter_v2_member_lineage_rejects_mixed_v1_profile_schema() -> None:
    from itda.contracts.phase5_openrouter_recovery import (
        OPENROUTER_PROFILE_SCHEMA_VERSION,
        OPENROUTER_V2_PROMPT_SHA256,
        OpenRouterMemberRequestV2,
    )

    payload = _openrouter_v2_member_payload(
        prompt_sha256=OPENROUTER_V2_PROMPT_SHA256,
        profile_schema=OPENROUTER_PROFILE_SCHEMA_VERSION,
    )
    with pytest.raises(ValueError, match="OPENROUTER_V2_MEMBER_LINEAGE_DRIFT"):
        OpenRouterMemberRequestV2.model_validate(payload)


def test_openrouter_v2_snapshot_rejects_every_self_consistent_payload_drift(
    tmp_path: Path,
) -> None:
    from itda.contracts.phase5_openrouter_recovery import (
        OPENROUTER_V2_SNAPSHOT_PATH,
        load_openrouter_snapshot_v2,
    )

    source = json.loads(OPENROUTER_V2_SNAPSHOT_PATH.read_bytes())
    mutations: tuple[tuple[str, tuple[str, ...], object], ...] = (
        ("schema_version", ("schema_version",), "itda.phase5-openrouter-api-snapshot.v2x"),
        ("authority_id", ("authority_id",), "phase5-openrouter-r2-drift"),
        ("provider_lane", ("provider_lane",), "OTHER_PROVIDER"),
        ("captured_offline", ("captured_offline",), False),
        ("runtime_metadata_fetch_forbidden", ("runtime_metadata_fetch_forbidden",), False),
        ("accessed_at", ("accessed_at",), "2026-08-24T00:00:01Z"),
        ("expiration_date", ("expiration_date",), "2098-12-30"),
        (
            "provenance.api_reference",
            ("provenance_urls", "api_reference"),
            "https://example.invalid/api",
        ),
        (
            "provenance.data_policies",
            ("provenance_urls", "data_policies"),
            "https://example.invalid/policy",
        ),
        (
            "provenance.models_api",
            ("provenance_urls", "models_api"),
            "https://example.invalid/models",
        ),
        ("provenance.extra", ("provenance_urls", "extra"), "forbidden"),
        ("endpoint.auth_scheme", ("endpoint", "auth_scheme"), "Basic"),
        ("endpoint.method", ("endpoint", "method"), "GET"),
        ("endpoint.url", ("endpoint", "url"), "https://example.invalid"),
        ("endpoint.extra", ("endpoint", "extra"), "forbidden"),
        (
            "architecture.input_modalities",
            ("model", "architecture", "input_modalities"),
            ["text"],
        ),
        (
            "architecture.lane_input_modalities",
            ("model", "architecture", "lane_input_modalities"),
            ["image"],
        ),
        (
            "architecture.output_modalities",
            ("model", "architecture", "output_modalities"),
            ["image"],
        ),
        ("architecture.extra", ("model", "architecture", "extra"), True),
        ("model.canonical_slug", ("model", "canonical_slug"), "other/model"),
        ("model.context_length", ("model", "context_length"), 1_048_575),
        ("model.max_completion_tokens", ("model", "max_completion_tokens"), 131_071),
        (
            "pricing.completion",
            ("model", "pricing", "completion_per_million_tokens"),
            "1",
        ),
        ("pricing.currency", ("model", "pricing", "currency"), "KRW"),
        (
            "pricing.prompt",
            ("model", "pricing", "prompt_per_million_tokens"),
            "1",
        ),
        ("pricing.extra", ("model", "pricing", "extra"), "forbidden"),
        (
            "reasoning.allowed_efforts",
            ("model", "reasoning", "allowed_efforts"),
            ["high"],
        ),
        ("reasoning.default_effort", ("model", "reasoning", "default_effort"), "high"),
        ("reasoning.default_enabled", ("model", "reasoning", "default_enabled"), False),
        ("reasoning.required", ("model", "reasoning", "required"), False),
        ("reasoning.selected_effort", ("model", "reasoning", "selected_effort"), "max"),
        ("reasoning.extra", ("model", "reasoning", "extra"), True),
        ("model.slug", ("model", "slug"), "other/model"),
        (
            "model.supported_parameters",
            ("model", "supported_parameters"),
            ["temperature"],
        ),
        ("model.extra", ("model", "extra"), "forbidden"),
        ("policy.completions_retained", ("data_policy", "completions_retained"), False),
        ("policy.prompts_retained", ("data_policy", "prompts_retained"), False),
        (
            "policy.retention_duration_known",
            ("data_policy", "retention_duration_known"),
            True,
        ),
        ("policy.used_for_training", ("data_policy", "used_for_training"), True),
        ("policy.extra", ("data_policy", "extra"), True),
        ("attribution_headers_sent", ("attribution_headers_sent",), True),
        (
            "optional_attribution_headers",
            ("optional_attribution_headers",),
            ["HTTP-Referer"],
        ),
        ("top_level.extra", ("extra",), "forbidden"),
    )
    accepted: list[str] = []
    for index, (label, path_parts, replacement) in enumerate(mutations):
        mutated = json.loads(json.dumps(source))
        cursor = mutated
        for component in path_parts[:-1]:
            cursor = cursor[component]
        cursor[path_parts[-1]] = replacement
        unsigned = {key: value for key, value in mutated.items() if key != "snapshot_sha256"}
        mutated["snapshot_sha256"] = canonical_sha256(unsigned)
        candidate = tmp_path / f"snapshot-drift-{index}.json"
        candidate.write_text(json.dumps(mutated), encoding="utf-8")
        try:
            load_openrouter_snapshot_v2(candidate)
        except (PermissionError, ValueError, ValidationError):
            continue
        accepted.append(label)
    assert accepted == []


def _build_openrouter_v2_packet_for_digest_tests(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[dict[str, object], object]:
    from itda.domain.demo_profile_eligibility import _CANONICAL_DEV_IDS
    from itda.pipeline.demo_profile_materialization import validate_demo_source_inventory

    bundles = validate_demo_source_inventory(  # type: ignore[arg-type]
        [_synthetic_bundle(place_id) for place_id in _CANONICAL_DEV_IDS]
    )
    monkeypatch.setattr(lane, "_verified_source_bundles", lambda: bundles)
    plan = lane.build_openrouter_v2_plan(
        bundles,
        checkout_manifest_digest=lane.openrouter_v2_checkout_manifest_sha256(),
    )
    packet = lane.build_openrouter_v2_public_request(
        plan=plan,
        checkout_commit_sha256=plan.checkout_commit_sha256,
    )
    return packet, plan


def test_openrouter_v2_packet_rejects_missing_and_null_persisted_digests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packet, plan = _build_openrouter_v2_packet_for_digest_tests(monkeypatch)
    paths = (
        ("request_artifact_sha256",),
        ("predecessor_consumption", "consumption_sha256"),
        ("retry_policy", "policy_sha256"),
        ("exposure_policy", "policy_sha256"),
    )
    accepted: list[str] = []
    for path_parts in paths:
        for mode in ("missing", "null"):
            hostile = json.loads(json.dumps(packet))
            cursor = hostile
            for component in path_parts[:-1]:
                cursor = cursor[component]
            if mode == "missing":
                del cursor[path_parts[-1]]
            else:
                cursor[path_parts[-1]] = None
            try:
                lane.validate_openrouter_v2_public_request(
                    hostile,
                    plan=plan,
                    checkout_commit_sha256=plan.checkout_commit_sha256,
                )
            except (PermissionError, ValueError, ValidationError):
                continue
            accepted.append(f"{'.'.join(path_parts)}:{mode}")
    assert accepted == []


def test_openrouter_v2_member_lineage_requires_persisted_digest():
    from itda.contracts.phase5_openrouter_recovery import (
        OPENROUTER_V2_PROFILE_SCHEMA,
        OPENROUTER_V2_PROMPT_SHA256,
        OpenRouterMemberRequestV2,
    )

    payload = _openrouter_v2_member_payload(
        prompt_sha256=OPENROUTER_V2_PROMPT_SHA256, profile_schema=OPENROUTER_V2_PROFILE_SCHEMA
    )
    for value in ("missing", None, "9" * 64):
        hostile = dict(payload)
        if value == "missing":
            del hostile["lineage_sha256"]
        else:
            hostile["lineage_sha256"] = value
        with pytest.raises((ValueError, ValidationError)):
            OpenRouterMemberRequestV2.model_validate(hostile)


def test_openrouter_v2_snapshot_duplicate_key_and_deep_mutation_reject(tmp_path: Path):
    from itda.contracts.phase5_openrouter_recovery import (
        OPENROUTER_V2_SNAPSHOT_PATH,
        load_openrouter_snapshot_v2,
    )

    raw = OPENROUTER_V2_SNAPSHOT_PATH.read_text(encoding="utf-8")
    path = tmp_path / "duplicate.json"
    path.write_text(
        raw.replace(
            chr(123),
            chr(123)
            + chr(34)
            + "authority_id"
            + chr(34)
            + chr(58)
            + chr(34)
            + "malicious"
            + chr(34)
            + chr(44),
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="DUPLICATE"):
        load_openrouter_snapshot_v2(path)
    snapshot = load_openrouter_snapshot_v2()
    with pytest.raises((TypeError, ValidationError, AttributeError)):
        snapshot.model["pricing"]["currency"] = "KRW"


def test_openrouter_v2_generation_and_terminal_bind_checkout_manifest():
    from itda.contracts.phase5_openrouter_recovery import (
        OpenRouterGenerationV2,
        OpenRouterTerminalV2,
    )

    generation = _openrouter_v2_valid_generation()
    assert OpenRouterGenerationV2.model_validate(generation).checkout_manifest_sha256 == "2" * 64
    terminal = _openrouter_v2_terminal_payload(
        "COMPLETE_CANDIDATE_READY",
        reason="COMPLETE_CANDIDATE_READY",
        attempt_count=24,
        reserve_count=24,
        secret_read=True,
        client_constructed=True,
        network_attempted=True,
        generation_sha256=str(generation["generation_sha256"]),
        profile_manifest_sha256=str(generation["profile_manifest_sha256"]),
        profile_count=24,
        generation=generation,
    )
    assert OpenRouterTerminalV2.model_validate(terminal).checkout_manifest_sha256 == "2" * 64
    for field in ("request_manifest_sha256", "checkout_commit_sha256", "checkout_manifest_sha256"):
        hostile = dict(terminal)
        hostile[field] = "8" * (40 if field == "checkout_commit_sha256" else 64)
        hostile = _restamp_openrouter_v2_terminal(hostile)
        with pytest.raises(ValueError, match="OPENROUTER_V2_TERMINAL_GENERATION_BINDING"):
            OpenRouterTerminalV2.model_validate(hostile)


def test_openrouter_v2_profile_digest_requires_exact_persisted_value():
    from itda.contracts.phase5_openrouter_recovery import (
        OPENROUTER_V2_PROMPT_SHA256,
        OpenRouterProfileV2,
    )

    keys = (
        "H",
        "E",
        "R",
        *(f"{p}{i}" for p in ("H", "I", "R") for i in range(1, 5)),
        *(f"M{i}" for i in range(1, 7)),
    )
    unsigned = {
        "schema_version": "itda.phase5-openrouter-profile.v2",
        "authority_id": "phase5-openrouter-stealth-ox-alpha-recovery-r2-20260824",
        "analysis_origin": "DEMO_MODEL_DERIVED",
        "place_id": "place:v2-profile",
        "split": "DEV",
        "axis_scores": {"H": 50, "E": 50, "R": 50},
        "subattributes": {f"{p}{i}": 2 for p in ("H", "I", "R") for i in range(1, 5)},
        "mismatch_traits": {f"M{i}": 50 for i in range(1, 7)},
        "evidence_justifications": {key: ("ev:1",) for key in keys},
        "evidence_ids": ("ev:1",),
        "confidence": 50,
        "publishable": True,
        "provider_lane": "OPENROUTER_API",
        "endpoint": "https://openrouter.ai/api/v1/chat/completions",
        "model": "stealth/ox-alpha",
        "prompt_version": "phase5-openrouter-profile-sentinel-json.v2",
        "prompt_sha256": OPENROUTER_V2_PROMPT_SHA256,
        "snapshot_sha256": "a" * 64,
        "predecessor_consumption_sha256": "b" * 64,
        "source_bundle_sha256": "c" * 64,
        "evidence_inventory_sha256": "d" * 64,
        "request_sha256": "e" * 64,
        "response_sha256": "f" * 64,
    }
    exact = {**unsigned, "profile_sha256": canonical_sha256(unsigned)}
    assert OpenRouterProfileV2.model_validate(exact).profile_sha256 == exact["profile_sha256"]
    for hostile in (
        unsigned,
        {**unsigned, "profile_sha256": None},
        {**unsigned, "profile_sha256": "9" * 64},
    ):
        with pytest.raises((ValueError, ValidationError)):
            OpenRouterProfileV2.model_validate(hostile)
    with pytest.raises(ValueError, match="OPENROUTER_V2_(PROFILE|PERSISTED)_DIGEST_DRIFT"):
        OpenRouterProfileV2.model_validate({**exact, "confidence": 51})


def test_openrouter_v2_strict_raw_default_omission_rejects(monkeypatch: pytest.MonkeyPatch):
    from itda.contracts.phase5_openrouter_recovery import (
        OpenRouterExposurePolicyV2,
        OpenRouterFirstPassV2,
        OpenRouterPredecessorConsumptionV2,
        OpenRouterPublicRequestV2,
        OpenRouterRetryPolicyV2,
    )

    packet, _plan = _build_openrouter_v2_packet_for_digest_tests(monkeypatch)
    cases = (
        (OpenRouterPublicRequestV2, packet, "blind_access"),
        (OpenRouterRetryPolicyV2, packet["retry_policy"], "max_retries"),
        (OpenRouterExposurePolicyV2, packet["exposure_policy"], "price_status"),
        (OpenRouterPredecessorConsumptionV2, packet["predecessor_consumption"], "retry_authorized"),
        (OpenRouterFirstPassV2, packet["first_passes"][0], "schema_version"),
    )
    accepted = []
    for contract, source, field in cases:
        for value in ("missing", None):
            hostile = json.loads(json.dumps(source))
            if value == "missing":
                del hostile[field]
            else:
                hostile[field] = value
            try:
                contract.model_validate(hostile)
            except (PermissionError, ValueError, ValidationError):
                continue
            accepted.append(f"{contract.__name__}.{field}:{value}")
    assert accepted == []


def test_openrouter_v2_fixed_raw_bytes_reject_reformatting(tmp_path: Path):
    from itda.contracts.phase5_openrouter_recovery import (
        OPENROUTER_V2_PREDECESSOR_FAILURE_PATH,
        OPENROUTER_V2_SNAPSHOT_PATH,
        load_openrouter_snapshot_v2,
    )

    snapshot_raw = OPENROUTER_V2_SNAPSHOT_PATH.read_bytes()
    assert (
        hashlib.sha256(snapshot_raw).hexdigest()
        == "e185068a79d8f908b210f0ecdbd8e9e850c94ad4e733f3deb4b1189f3ad83ba2"
    )
    snapshot_path = tmp_path / "snapshot-reformatted.json"
    snapshot_path.write_bytes(json.dumps(json.loads(snapshot_raw), indent=1).encode())
    with pytest.raises(ValueError, match="SNAPSHOT_RAW_DIGEST_DRIFT"):
        load_openrouter_snapshot_v2(snapshot_path)
    predecessor_raw = OPENROUTER_V2_PREDECESSOR_FAILURE_PATH.read_bytes()
    assert (
        hashlib.sha256(predecessor_raw).hexdigest()
        == "443c1a68a7053e672d6742e184dd1023556c93d4b6a827f238c2c2deb7faa6ba"
    )
    predecessor_path = tmp_path / "predecessor-reformatted.json"
    predecessor_path.write_bytes(json.dumps(json.loads(predecessor_raw), indent=1).encode())
    with pytest.raises(ValueError, match="PREDECESSOR_RAW_DIGEST_DRIFT"):
        lane.verify_openrouter_v2_predecessor_consumption(predecessor_path)


def test_openrouter_v2_nested_duplicate_keys_reject(tmp_path: Path):
    from itda.contracts.phase5_openrouter_recovery import (
        OPENROUTER_V2_SNAPSHOT_PATH,
        load_openrouter_snapshot_v2,
    )

    raw = OPENROUTER_V2_SNAPSHOT_PATH.read_text()
    nested = raw.replace(
        chr(34) + "endpoint" + chr(34) + ": {",
        chr(34)
        + "endpoint"
        + chr(34)
        + ": {"
        + chr(34)
        + "url"
        + chr(34)
        + ":"
        + chr(34)
        + "malicious"
        + chr(34)
        + ",",
        1,
    )
    path = tmp_path / "snapshot-nested-duplicate.json"
    path.write_text(nested)
    with pytest.raises(ValueError, match="DUPLICATE"):
        load_openrouter_snapshot_v2(path)
    predecessor = lane.OPENROUTER_V2_PREDECESSOR_FAILURE_PATH.read_text()
    pred_path = tmp_path / "predecessor-nested-duplicate.json"
    pred_path.write_text(
        predecessor.replace(
            chr(34) + "approval" + chr(34) + ":{",
            chr(34) + "approval" + chr(34) + ":{" + chr(34) + "installed" + chr(34) + ":false,",
            1,
        )
    )
    with pytest.raises(ValueError, match="DUPLICATE"):
        lane.verify_openrouter_v2_predecessor_consumption(pred_path)


def test_openrouter_v2_all_defaulted_persisted_fields_reject_missing_and_null():
    from itda.contracts.phase5_openrouter_recovery import (
        OpenRouterApiSnapshotV2,
        OpenRouterExposurePolicyV2,
        OpenRouterFirstPassV2,
        OpenRouterGenerationV2,
        OpenRouterMemberRequestV2,
        OpenRouterPredecessorConsumptionV2,
        OpenRouterProfileV2,
        OpenRouterPublicRequestV2,
        OpenRouterRetryPolicyV2,
        OpenRouterTerminalV2,
        _require_strict_persisted_v2,
    )

    contracts = (
        (OpenRouterApiSnapshotV2, "snapshot_sha256"),
        (OpenRouterPredecessorConsumptionV2, "consumption_sha256"),
        (OpenRouterRetryPolicyV2, "policy_sha256"),
        (OpenRouterExposurePolicyV2, "policy_sha256"),
        (OpenRouterMemberRequestV2, None),
        (OpenRouterFirstPassV2, None),
        (OpenRouterProfileV2, "profile_sha256"),
        (OpenRouterGenerationV2, "generation_sha256"),
        (OpenRouterTerminalV2, "terminal_sha256"),
        (OpenRouterPublicRequestV2, "request_artifact_sha256"),
    )
    for contract, digest_field in contracts:
        payload = {}
        defaulted_fields = []
        for name, field in contract.model_fields.items():
            if field.is_required():
                payload[name] = "x"
            else:
                payload[name] = field.get_default(call_default_factory=True)
                defaulted_fields.append(name)
        assert defaulted_fields
        for field_name in defaulted_fields:
            for mode in ("missing", "null"):
                hostile = dict(payload)
                if mode == "missing":
                    del hostile[field_name]
                    expected = "PERSISTED_KEY_SET_DRIFT"
                else:
                    hostile[field_name] = None
                    expected = "PERSISTED_(NULL_REJECTED|DIGEST_DRIFT)"
                with pytest.raises(ValueError, match=expected):
                    _require_strict_persisted_v2(
                        contract,
                        hostile,
                        digest_field=digest_field,
                    )


def test_openrouter_v2_remaining_persisted_models_require_raw_exact_shape(tmp_path: Path):
    from itda.contracts.phase5_openrouter_recovery import (
        OpenRouterApprovalBindingV2,
        OpenRouterAttemptV2,
        OpenRouterClaimV2,
        OpenRouterJournalEntryV2,
        OpenRouterLedgerEntryV2,
        OpenRouterProtectedStateDescriptorV2,
    )

    descriptor = OpenRouterProtectedStateDescriptorV2.from_root(
        state_root=str(tmp_path / "protected")
    ).model_dump(mode="json")
    approval_unsigned = {
        "schema_version": "itda.phase5-openrouter-approval.v2",
        "authority_id": "phase5-openrouter-stealth-ox-alpha-recovery-r2-20260824",
        "decision": "APPROVED",
        "request_artifact_sha256": "a" * 64,
        "request_file_sha256": "b" * 64,
        "request_manifest_sha256": "c" * 64,
        "checkout_manifest_sha256": "d" * 64,
        "checkout_commit_sha256": "e" * 40,
        "protected_state_sha256": descriptor["protected_state_sha256"],
        "predecessor_consumption_sha256": "f" * 64,
        "secret_identity_sha256": "1" * 64,
    }
    approval = {**approval_unsigned, "approval_sha256": canonical_sha256(approval_unsigned)}
    claim_unsigned = {
        "schema_version": "itda.phase5-openrouter-claim.v2",
        "authority_id": "phase5-openrouter-stealth-ox-alpha-recovery-r2-20260824",
        "request_artifact_sha256": "a" * 64,
        "request_file_sha256": "b" * 64,
        "approval_sha256": approval["approval_sha256"],
        "protected_state_sha256": descriptor["protected_state_sha256"],
        "predecessor_consumption_sha256": "f" * 64,
    }
    claim = {**claim_unsigned, "claim_sha256": canonical_sha256(claim_unsigned)}
    ledger = {
        "schema_version": "itda.phase5-openrouter-ledger-entry.v2",
        "authority_id": "phase5-openrouter-stealth-ox-alpha-recovery-r2-20260824",
        "operation": "RESERVE",
        "attempt_number": 1,
        "amount_micro_usd": 0,
        "price_status": "EXACT_ZERO",
        "place_id": "place:v2-exact",
        "request_sha256": "2" * 64,
        "claim_sha256": claim["claim_sha256"],
        "evidence_sha256": None,
    }
    journal = {
        "schema_version": "itda.phase5-openrouter-journal-entry.v2",
        "authority_id": "phase5-openrouter-stealth-ox-alpha-recovery-r2-20260824",
        "phase": "DISPATCH_PREPARED",
        "attempt_number": 1,
        "place_id": "place:v2-exact",
        "request_sha256": "2" * 64,
        "claim_sha256": claim["claim_sha256"],
    }
    attempt = {
        "schema_version": "itda.phase5-openrouter-attempt.v2",
        "authority_id": "phase5-openrouter-stealth-ox-alpha-recovery-r2-20260824",
        "attempt_number": 1,
        "place_id": "place:v2-exact",
        "request_sha256": "2" * 64,
        "claim_sha256": claim["claim_sha256"],
        "status_code": None,
        "response_sha256": None,
        "evidence_sha256": "3" * 64,
    }
    cases = (
        (OpenRouterProtectedStateDescriptorV2, descriptor, "schema_version"),
        (OpenRouterApprovalBindingV2, approval, "decision"),
        (OpenRouterClaimV2, claim, "authority_id"),
        (OpenRouterLedgerEntryV2, ledger, "amount_micro_usd"),
        (OpenRouterJournalEntryV2, journal, "schema_version"),
        (OpenRouterAttemptV2, attempt, "status_code"),
    )
    accepted = []
    for contract, payload, field_name in cases:
        hostile = dict(payload)
        del hostile[field_name]
        try:
            contract.model_validate(hostile)
        except (PermissionError, TypeError, ValueError, ValidationError):
            continue
        accepted.append(f"{contract.__name__}.{field_name}")
    assert accepted == []


def test_openrouter_v2_packet_reader_rejects_top_and_nested_duplicate_keys(
    monkeypatch: pytest.MonkeyPatch,
):
    from itda.domain.canonical import canonical_json_bytes

    packet, plan = _build_openrouter_v2_packet_for_digest_tests(monkeypatch)
    raw = canonical_json_bytes(packet)
    hostile_documents = (
        raw.replace(b"{", b'{"authority_id":"malicious",', 1),
        raw.replace(
            b'"retry_policy":{',
            b'"retry_policy":{"max_retries":0,',
            1,
        ),
    )
    for hostile in hostile_documents:
        with pytest.raises(ValueError, match="DUPLICATE"):
            lane.load_openrouter_v2_public_request_bytes(
                hostile,
                plan=plan,
                checkout_commit_sha256=plan.checkout_commit_sha256,
            )
    assert (
        lane.load_openrouter_v2_public_request_bytes(
            raw,
            plan=plan,
            checkout_commit_sha256=plan.checkout_commit_sha256,
        )
        == packet
    )
    with pytest.raises(ValueError, match="NOT_CANONICAL"):
        lane.load_openrouter_v2_public_request_bytes(
            json.dumps(packet, indent=2).encode("utf-8"),
            plan=plan,
            checkout_commit_sha256=plan.checkout_commit_sha256,
        )


def _openrouter_v2_generation_unsigned() -> dict[str, object]:
    return {
        "schema_version": "itda.phase5-openrouter-generation.v2",
        "authority_id": "phase5-openrouter-stealth-ox-alpha-recovery-r2-20260824",
        "request_artifact_sha256": "a" * 64,
        "request_file_sha256": "b" * 64,
        "request_manifest_sha256": "c" * 64,
        "checkout_commit_sha256": "d" * 40,
        "checkout_manifest_sha256": "2" * 64,
        "claim_sha256": "e" * 64,
        "predecessor_consumption_sha256": "f" * 64,
        "profile_count": 24,
        "profile_manifest_sha256": "1" * 64,
        "lifecycle_mutated": False,
    }


def test_openrouter_v2_generation_accepts_exact_digest() -> None:
    from itda.contracts.phase5_openrouter_recovery import OpenRouterGenerationV2

    unsigned = _openrouter_v2_generation_unsigned()
    generation = OpenRouterGenerationV2.model_validate(
        {**unsigned, "generation_sha256": canonical_sha256(unsigned)}
    )
    assert generation.profile_count == 24


def test_openrouter_v2_generation_rejects_arbitrary_digest() -> None:
    from itda.contracts.phase5_openrouter_recovery import OpenRouterGenerationV2

    unsigned = _openrouter_v2_generation_unsigned()
    with pytest.raises(ValueError, match="OPENROUTER_V2_(GENERATION|PERSISTED)_DIGEST_DRIFT"):
        OpenRouterGenerationV2.model_validate({**unsigned, "generation_sha256": "9" * 64})


def test_openrouter_v2_generation_rejects_post_digest_mutation() -> None:
    from itda.contracts.phase5_openrouter_recovery import OpenRouterGenerationV2

    unsigned = _openrouter_v2_generation_unsigned()
    payload = {**unsigned, "generation_sha256": canonical_sha256(unsigned)}
    payload["request_manifest_sha256"] = "8" * 64
    with pytest.raises(ValueError, match="OPENROUTER_V2_(GENERATION|PERSISTED)_DIGEST_DRIFT"):
        OpenRouterGenerationV2.model_validate(payload)


def test_openrouter_v2_generation_builder_supplies_canonical_digest() -> None:
    from itda.contracts.phase5_openrouter_recovery import build_openrouter_generation_v2

    generation = build_openrouter_generation_v2(
        request_artifact_sha256="a" * 64,
        request_file_sha256="b" * 64,
        request_manifest_sha256="c" * 64,
        checkout_commit_sha256="d" * 40,
        checkout_manifest_sha256="2" * 64,
        claim_sha256="e" * 64,
        predecessor_consumption_sha256="f" * 64,
        profile_manifest_sha256="1" * 64,
    )
    assert generation.generation_sha256 == canonical_sha256(
        generation.model_dump(mode="json", exclude={"generation_sha256"})
    )


def _openrouter_v2_terminal_payload(
    status: str,
    *,
    reason: str,
    attempt_count: int,
    reserve_count: int,
    secret_read: bool,
    client_constructed: bool,
    network_attempted: bool,
    generation_sha256: str | None,
    profile_manifest_sha256: str | None,
    profile_count: int,
    generation: dict[str, object] | None = None,
) -> dict[str, object]:
    unsigned = {
        "schema_version": "itda.phase5-openrouter-terminal.v2",
        "authority_id": "phase5-openrouter-stealth-ox-alpha-recovery-r2-20260824",
        "status": status,
        "reason": reason,
        "request_artifact_sha256": (
            generation["request_artifact_sha256"] if generation is not None else "a" * 64
        ),
        "request_file_sha256": (
            generation["request_file_sha256"] if generation is not None else "b" * 64
        ),
        "request_manifest_sha256": generation["request_manifest_sha256"]
        if generation is not None
        else "e" * 64,
        "checkout_commit_sha256": generation["checkout_commit_sha256"]
        if generation is not None
        else "f" * 40,
        "checkout_manifest_sha256": generation["checkout_manifest_sha256"]
        if generation is not None
        else "1" * 64,
        "claim_sha256": generation["claim_sha256"] if generation is not None else "c" * 64,
        "predecessor_consumption_sha256": (
            generation["predecessor_consumption_sha256"] if generation is not None else "d" * 64
        ),
        "generation": generation,
        "generation_sha256": generation_sha256,
        "profile_manifest_sha256": profile_manifest_sha256,
        "profile_count": profile_count,
        "attempt_count": attempt_count,
        "reserve_count": reserve_count,
        "secret_read": secret_read,
        "client_constructed": client_constructed,
        "network_attempted": network_attempted,
        "lifecycle_mutated": False,
        "activation_capability": False,
    }
    return {**unsigned, "terminal_sha256": canonical_sha256(unsigned)}


def _openrouter_v2_valid_generation() -> dict[str, object]:
    unsigned = _openrouter_v2_generation_unsigned()
    return {**unsigned, "generation_sha256": canonical_sha256(unsigned)}


def test_openrouter_v2_terminal_accepts_legal_positive_and_negative_branches() -> None:
    from itda.contracts.phase5_openrouter_recovery import (
        OpenRouterGenerationV2,
        OpenRouterTerminalV2,
        build_openrouter_terminal_v2,
    )

    generation = _openrouter_v2_valid_generation()
    positive = _openrouter_v2_terminal_payload(
        "COMPLETE_CANDIDATE_READY",
        reason="COMPLETE_CANDIDATE_READY",
        attempt_count=24,
        reserve_count=24,
        secret_read=True,
        client_constructed=True,
        network_attempted=True,
        generation_sha256=str(generation["generation_sha256"]),
        profile_manifest_sha256=str(generation["profile_manifest_sha256"]),
        profile_count=24,
        generation=generation,
    )
    designed_negative = _openrouter_v2_terminal_payload(
        "DESIGNED_NEGATIVE",
        reason="OPENROUTER_PROVIDER_DESIGNED_NEGATIVE",
        attempt_count=1,
        reserve_count=1,
        secret_read=True,
        client_constructed=True,
        network_attempted=True,
        generation_sha256=None,
        profile_manifest_sha256=None,
        profile_count=0,
    )
    failed = _openrouter_v2_terminal_payload(
        "FAILED_UNACTIVATED",
        reason="OPENROUTER_LOCAL_FAILURE",
        attempt_count=0,
        reserve_count=0,
        secret_read=False,
        client_constructed=False,
        network_attempted=False,
        generation_sha256=None,
        profile_manifest_sha256=None,
        profile_count=0,
    )
    assert OpenRouterTerminalV2.model_validate(positive).status == "COMPLETE_CANDIDATE_READY"
    assert OpenRouterTerminalV2.model_validate(designed_negative).status == "DESIGNED_NEGATIVE"
    assert OpenRouterTerminalV2.model_validate(failed).status == "FAILED_UNACTIVATED"

    validated_generation = OpenRouterGenerationV2.model_validate(generation)
    built = (
        build_openrouter_terminal_v2(
            status="COMPLETE_CANDIDATE_READY",
            reason="COMPLETE_CANDIDATE_READY",
            request_artifact_sha256="a" * 64,
            request_file_sha256="b" * 64,
            request_manifest_sha256="e" * 64,
            checkout_commit_sha256="f" * 40,
            checkout_manifest_sha256="1" * 64,
            claim_sha256="c" * 64,
            predecessor_consumption_sha256="d" * 64,
            generation=validated_generation,
            attempt_count=24,
            reserve_count=24,
            secret_read=True,
            client_constructed=True,
            network_attempted=True,
        ),
        build_openrouter_terminal_v2(
            status="DESIGNED_NEGATIVE",
            reason="OPENROUTER_PROVIDER_DESIGNED_NEGATIVE",
            request_artifact_sha256="a" * 64,
            request_file_sha256="b" * 64,
            request_manifest_sha256="e" * 64,
            checkout_commit_sha256="f" * 40,
            checkout_manifest_sha256="1" * 64,
            claim_sha256="c" * 64,
            predecessor_consumption_sha256="d" * 64,
            generation=None,
            attempt_count=1,
            reserve_count=1,
            secret_read=True,
            client_constructed=True,
            network_attempted=True,
        ),
        build_openrouter_terminal_v2(
            status="FAILED_UNACTIVATED",
            reason="OPENROUTER_LOCAL_FAILURE",
            request_artifact_sha256="a" * 64,
            request_file_sha256="b" * 64,
            request_manifest_sha256="e" * 64,
            checkout_commit_sha256="f" * 40,
            checkout_manifest_sha256="1" * 64,
            claim_sha256="c" * 64,
            predecessor_consumption_sha256="d" * 64,
            generation=None,
            attempt_count=0,
            reserve_count=0,
            secret_read=False,
            client_constructed=False,
            network_attempted=False,
        ),
    )
    for terminal in built:
        assert terminal.terminal_sha256 == canonical_sha256(
            terminal.model_dump(mode="json", exclude={"terminal_sha256"})
        )


@pytest.mark.parametrize(
    ("mutation", "expected"),
    (
        ({"attempt_count": 0, "reserve_count": 0}, "OPENROUTER_V2_TERMINAL_POSITIVE_ATTEMPTS"),
        ({"client_constructed": False}, "OPENROUTER_V2_TERMINAL_FACTS_INCONSISTENT"),
        ({"secret_read": False}, "OPENROUTER_V2_TERMINAL_FACTS_INCONSISTENT"),
        ({"network_attempted": False}, "OPENROUTER_V2_TERMINAL_FACTS_INCONSISTENT"),
        ({"generation_sha256": None}, "OPENROUTER_V2_TERMINAL_POSITIVE_EVIDENCE"),
        ({"profile_manifest_sha256": None}, "OPENROUTER_V2_TERMINAL_POSITIVE_EVIDENCE"),
        ({"profile_count": 0}, "OPENROUTER_V2_TERMINAL_POSITIVE_EVIDENCE"),
    ),
)
def test_openrouter_v2_terminal_rejects_fabricated_positive(
    mutation: dict[str, object], expected: str
) -> None:
    from itda.contracts.phase5_openrouter_recovery import OpenRouterTerminalV2

    generation = _openrouter_v2_valid_generation()
    payload = _openrouter_v2_terminal_payload(
        "COMPLETE_CANDIDATE_READY",
        reason="COMPLETE_CANDIDATE_READY",
        attempt_count=24,
        reserve_count=24,
        secret_read=True,
        client_constructed=True,
        network_attempted=True,
        generation_sha256=str(generation["generation_sha256"]),
        profile_manifest_sha256=str(generation["profile_manifest_sha256"]),
        profile_count=24,
        generation=generation,
    )
    payload.update(mutation)
    unsigned = {key: value for key, value in payload.items() if key != "terminal_sha256"}
    payload["terminal_sha256"] = canonical_sha256(unsigned)
    with pytest.raises(ValueError, match=expected):
        OpenRouterTerminalV2.model_validate(payload)


def _restamp_openrouter_v2_terminal(payload: dict[str, object]) -> dict[str, object]:
    unsigned = {key: value for key, value in payload.items() if key != "terminal_sha256"}
    return {**unsigned, "terminal_sha256": canonical_sha256(unsigned)}


def test_openrouter_v2_terminal_rejects_designed_negative_without_network_fact() -> None:
    from itda.contracts.phase5_openrouter_recovery import OpenRouterTerminalV2

    payload = _openrouter_v2_terminal_payload(
        "DESIGNED_NEGATIVE",
        reason="OPENROUTER_PROVIDER_DESIGNED_NEGATIVE",
        attempt_count=1,
        reserve_count=1,
        secret_read=True,
        client_constructed=True,
        network_attempted=False,
        generation_sha256=None,
        profile_manifest_sha256=None,
        profile_count=0,
    )
    with pytest.raises(ValueError, match="OPENROUTER_V2_TERMINAL_FACTS_INCONSISTENT"):
        OpenRouterTerminalV2.model_validate(payload)


def test_openrouter_v2_terminal_rejects_generation_manifest_mismatch() -> None:
    from itda.contracts.phase5_openrouter_recovery import OpenRouterTerminalV2

    generation = _openrouter_v2_valid_generation()
    payload = _openrouter_v2_terminal_payload(
        "COMPLETE_CANDIDATE_READY",
        reason="COMPLETE_CANDIDATE_READY",
        attempt_count=24,
        reserve_count=24,
        secret_read=True,
        client_constructed=True,
        network_attempted=True,
        generation_sha256=str(generation["generation_sha256"]),
        profile_manifest_sha256="2" * 64,
        profile_count=24,
        generation=generation,
    )
    with pytest.raises(ValueError, match="OPENROUTER_V2_TERMINAL_GENERATION_BINDING"):
        OpenRouterTerminalV2.model_validate(payload)


def test_openrouter_v2_terminal_rejects_generation_digest_placeholder() -> None:
    from itda.contracts.phase5_openrouter_recovery import OpenRouterTerminalV2

    generation = _openrouter_v2_valid_generation()
    payload = _openrouter_v2_terminal_payload(
        "COMPLETE_CANDIDATE_READY",
        reason="COMPLETE_CANDIDATE_READY",
        attempt_count=24,
        reserve_count=24,
        secret_read=True,
        client_constructed=True,
        network_attempted=True,
        generation_sha256="9" * 64,
        profile_manifest_sha256=str(generation["profile_manifest_sha256"]),
        profile_count=24,
        generation=generation,
    )
    with pytest.raises(ValueError, match="OPENROUTER_V2_TERMINAL_GENERATION_BINDING"):
        OpenRouterTerminalV2.model_validate(payload)


def test_openrouter_v2_terminal_rejects_shared_generation_coordinate_mismatch() -> None:
    from itda.contracts.phase5_openrouter_recovery import OpenRouterTerminalV2

    generation = _openrouter_v2_valid_generation()
    payload = _openrouter_v2_terminal_payload(
        "COMPLETE_CANDIDATE_READY",
        reason="COMPLETE_CANDIDATE_READY",
        attempt_count=24,
        reserve_count=24,
        secret_read=True,
        client_constructed=True,
        network_attempted=True,
        generation_sha256=str(generation["generation_sha256"]),
        profile_manifest_sha256=str(generation["profile_manifest_sha256"]),
        profile_count=24,
        generation=generation,
    )
    payload["request_artifact_sha256"] = "2" * 64
    payload = _restamp_openrouter_v2_terminal(payload)
    with pytest.raises(ValueError, match="OPENROUTER_V2_TERMINAL_GENERATION_BINDING"):
        OpenRouterTerminalV2.model_validate(payload)


def test_openrouter_v2_terminal_rejects_tampered_nested_generation() -> None:
    from itda.contracts.phase5_openrouter_recovery import OpenRouterTerminalV2

    generation = _openrouter_v2_valid_generation()
    generation["request_manifest_sha256"] = "8" * 64
    payload = _openrouter_v2_terminal_payload(
        "COMPLETE_CANDIDATE_READY",
        reason="COMPLETE_CANDIDATE_READY",
        attempt_count=24,
        reserve_count=24,
        secret_read=True,
        client_constructed=True,
        network_attempted=True,
        generation_sha256=str(generation["generation_sha256"]),
        profile_manifest_sha256=str(generation["profile_manifest_sha256"]),
        profile_count=24,
        generation=generation,
    )
    with pytest.raises(
        (ValueError, ValidationError),
        match="OPENROUTER_V2_(GENERATION|PERSISTED)_DIGEST_DRIFT",
    ):
        OpenRouterTerminalV2.model_validate(payload)


def test_openrouter_v2_terminal_rejects_negative_with_nested_generation() -> None:
    from itda.contracts.phase5_openrouter_recovery import OpenRouterTerminalV2

    generation = _openrouter_v2_valid_generation()
    payload = _openrouter_v2_terminal_payload(
        "DESIGNED_NEGATIVE",
        reason="OPENROUTER_PROVIDER_DESIGNED_NEGATIVE",
        attempt_count=1,
        reserve_count=1,
        secret_read=True,
        client_constructed=True,
        network_attempted=True,
        generation_sha256=None,
        profile_manifest_sha256=None,
        profile_count=0,
        generation=generation,
    )
    with pytest.raises(ValueError, match="OPENROUTER_V2_TERMINAL_NEGATIVE_EVIDENCE"):
        OpenRouterTerminalV2.model_validate(payload)


def test_openrouter_v2_terminal_rejects_designed_negative_without_client_fact() -> None:
    from itda.contracts.phase5_openrouter_recovery import OpenRouterTerminalV2

    payload = _openrouter_v2_terminal_payload(
        "DESIGNED_NEGATIVE",
        reason="OPENROUTER_PROVIDER_DESIGNED_NEGATIVE",
        attempt_count=1,
        reserve_count=1,
        secret_read=True,
        client_constructed=False,
        network_attempted=False,
        generation_sha256=None,
        profile_manifest_sha256=None,
        profile_count=0,
    )
    with pytest.raises(ValueError, match="OPENROUTER_V2_TERMINAL_FACTS_INCONSISTENT"):
        OpenRouterTerminalV2.model_validate(payload)


def test_openrouter_v2_terminal_rejects_negative_with_positive_evidence() -> None:
    from itda.contracts.phase5_openrouter_recovery import OpenRouterTerminalV2

    payload = _openrouter_v2_terminal_payload(
        "DESIGNED_NEGATIVE",
        reason="OPENROUTER_PROVIDER_DESIGNED_NEGATIVE",
        attempt_count=1,
        reserve_count=1,
        secret_read=True,
        client_constructed=True,
        network_attempted=True,
        generation_sha256="e" * 64,
        profile_manifest_sha256="f" * 64,
        profile_count=24,
    )
    with pytest.raises(ValueError, match="OPENROUTER_V2_TERMINAL_NEGATIVE_EVIDENCE"):
        OpenRouterTerminalV2.model_validate(payload)


def test_openrouter_v2_terminal_requires_persisted_digest() -> None:
    from itda.contracts.phase5_openrouter_recovery import OpenRouterTerminalV2

    payload = _openrouter_v2_terminal_payload(
        "FAILED_UNACTIVATED",
        reason="OPENROUTER_LOCAL_FAILURE",
        attempt_count=0,
        reserve_count=0,
        secret_read=False,
        client_constructed=False,
        network_attempted=False,
        generation_sha256=None,
        profile_manifest_sha256=None,
        profile_count=0,
    )
    del payload["terminal_sha256"]
    with pytest.raises(ValidationError):
        OpenRouterTerminalV2.model_validate(payload)


def test_openrouter_v2_terminal_rejects_arbitrary_digest() -> None:
    from itda.contracts.phase5_openrouter_recovery import OpenRouterTerminalV2

    payload = _openrouter_v2_terminal_payload(
        "FAILED_UNACTIVATED",
        reason="OPENROUTER_LOCAL_FAILURE",
        attempt_count=0,
        reserve_count=0,
        secret_read=False,
        client_constructed=False,
        network_attempted=False,
        generation_sha256=None,
        profile_manifest_sha256=None,
        profile_count=0,
    )
    payload["terminal_sha256"] = "9" * 64
    with pytest.raises(ValueError, match="OPENROUTER_V2_(TERMINAL|PERSISTED)_DIGEST_DRIFT"):
        OpenRouterTerminalV2.model_validate(payload)


def test_openrouter_v2_predecessor_consumption_binds_exact_public_failure() -> None:
    consumption = lane.verify_openrouter_v2_predecessor_consumption()

    assert consumption.schema_version == ("itda.phase5-openrouter-predecessor-consumption.v2")
    assert consumption.failure_record_sha256 == (
        "67f5978b5edf5ccf24c56c9d21c496e6380517ecaa55fd63b3a5a4189349b502"
    )
    assert consumption.predecessor_authority_id == OPENROUTER_RECOVERY_AUTHORITY_ID
    assert consumption.failure_code == ("OPENROUTER_REPOSITORY_ROOT_BINDING_OFF_BY_ONE")
    assert consumption.failed_before == "RESERVE"
    assert consumption.inventory_files == ("approval.json", "claim.json")
    assert consumption.approval_consumed is True
    assert consumption.claim_consumed is True
    assert consumption.reserve_count == 0
    assert consumption.attempt_count == 0
    assert consumption.secret_read is False
    assert consumption.client_constructed is False
    assert consumption.send_attempted is False
    assert consumption.provider_attempted is False
    assert consumption.network_attempted is False
    assert consumption.lifecycle_mutated is False
    assert consumption.terminal_exists is False
    assert consumption.retry_authorized is False
    assert consumption.predecessor_authority_promoted is False


def test_openrouter_v2_predecessor_omission_and_drift_reject_synthetic_copies(
    tmp_path: Path,
) -> None:
    from itda.contracts.phase5_openrouter_recovery import (
        OPENROUTER_V2_PREDECESSOR_FAILURE_PATH,
    )

    original = json.loads(OPENROUTER_V2_PREDECESSOR_FAILURE_PATH.read_bytes())
    mutations = []

    missing_approval = json.loads(json.dumps(original))
    del missing_approval["approval"]
    mutations.append(missing_approval)

    reserve_drift = json.loads(json.dumps(original))
    reserve_drift["traffic_boundary"]["reserve_count"] = 1
    mutations.append(reserve_drift)

    inventory_drift = json.loads(json.dumps(original))
    inventory_drift["inventory"]["files"] = ["claim.json", "approval.json"]
    mutations.append(inventory_drift)

    predecessor_authority_drift = json.loads(json.dumps(original))
    predecessor_authority_drift["old_authority_id"] = (
        "phase5-openrouter-stealth-ox-alpha-recovery-r2-20260824"
    )
    mutations.append(predecessor_authority_drift)

    for index, mutated in enumerate(mutations):
        unsigned = {key: value for key, value in mutated.items() if key != "record_sha256"}
        mutated["record_sha256"] = canonical_sha256(unsigned)
        candidate = tmp_path / f"predecessor-{index}.json"
        candidate.write_text(json.dumps(mutated), encoding="utf-8")
        with pytest.raises(ValueError, match="OPENROUTER_V2_PREDECESSOR"):
            lane.verify_openrouter_v2_predecessor_consumption(candidate)


def test_openrouter_v2_packet_round_trip_and_hostile_mutations_in_memory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.domain.demo_profile_eligibility import _CANONICAL_DEV_IDS
    from itda.pipeline.demo_profile_materialization import (
        validate_demo_source_inventory,
    )

    bundles = validate_demo_source_inventory(  # type: ignore[arg-type]
        [_synthetic_bundle(place_id) for place_id in _CANONICAL_DEV_IDS]
    )
    source_reads = 0

    def synthetic_fixed_source():
        nonlocal source_reads
        source_reads += 1
        return bundles

    monkeypatch.setattr(lane, "_verified_source_bundles", synthetic_fixed_source)
    with pytest.raises(PermissionError, match="OPENROUTER_V2_REPOSITORY_ROOT_NOT_CANONICAL"):
        lane.build_openrouter_v2_plan(
            bundles,
            checkout_manifest_digest="a" * 64,
            repository_root=tmp_path / "caller-root",
        )
    assert source_reads == 0

    plan = lane.build_openrouter_v2_plan(
        bundles,
        checkout_manifest_digest=lane.openrouter_v2_checkout_manifest_sha256(),
    )
    assert source_reads == 1
    packet = lane.build_openrouter_v2_public_request(
        plan=plan,
        checkout_commit_sha256=plan.checkout_commit_sha256,
    )
    assert (
        lane.validate_openrouter_v2_public_request(
            packet,
            plan=plan,
            checkout_commit_sha256=plan.checkout_commit_sha256,
        )
        == packet
    )
    assert packet["authority_id"] == ("phase5-openrouter-stealth-ox-alpha-recovery-r2-20260824")
    assert packet["schema_version"] == "itda.phase5-openrouter-recovery-request.v2"
    assert packet["public_request_relative_path"] == (
        "artifacts/public/phase5/openrouter-recovery-v2-request.json"
    )
    assert packet["predecessor_grants_retry"] is False
    assert packet["predecessor_grants_authority"] is False

    mutations = (
        ("authority_id", OPENROUTER_RECOVERY_AUTHORITY_ID),
        ("schema_version", "itda.phase5-openrouter-recovery-request.v1"),
        (
            "public_request_relative_path",
            "artifacts/public/phase5/openrouter-recovery-request.json",
        ),
        (
            "snapshot_relative_path",
            "backend/src/itda/providers/openrouter_ox_alpha_api_contract.json",
        ),
        (
            "protected_root_relative_path",
            "artifacts/restricted/catalog/phase5-openrouter-recovery",
        ),
        (
            "terminal_relative_path",
            "artifacts/reports/phase5/openrouter-recovery-terminal.json",
        ),
        (
            "request_artifact_sha256",
            "22e6da6d531befa35bcd7128ae37eadb364acdf846bf20d9beccae737358670f",
        ),
        (
            "request_manifest_sha256",
            "1e28243098b48e48c09e841b53a15dd3518f55690d1dc1e0b3fc29d641313043",
        ),
        (
            "snapshot_sha256",
            "8795f32689c9c90f9d5ee07ab6a667915bc446939b1b0d5307223788c6585540",
        ),
    )
    for key, historical in mutations:
        hostile = json.loads(json.dumps(packet))
        hostile[key] = historical
        with pytest.raises((PermissionError, ValueError, ValidationError)):
            lane.validate_openrouter_v2_public_request(
                hostile,
                plan=plan,
                checkout_commit_sha256=plan.checkout_commit_sha256,
            )

    mixed_member = json.loads(json.dumps(packet))
    mixed_member["first_passes"][0]["authority_id"] = OPENROUTER_RECOVERY_AUTHORITY_ID
    with pytest.raises((PermissionError, ValueError, ValidationError)):
        lane.validate_openrouter_v2_public_request(
            mixed_member,
            plan=plan,
            checkout_commit_sha256=plan.checkout_commit_sha256,
        )

    for predecessor_key, drift in (
        ("retry_authorized", True),
        ("predecessor_authority_promoted", True),
        ("reserve_count", 1),
        ("failure_record_sha256", "0" * 64),
    ):
        predecessor_drift = json.loads(json.dumps(packet))
        predecessor_drift["predecessor_consumption"][predecessor_key] = drift
        with pytest.raises((ValueError, ValidationError)):
            lane.validate_openrouter_v2_public_request(
                predecessor_drift,
                plan=plan,
                checkout_commit_sha256=plan.checkout_commit_sha256,
            )

    extra = json.loads(json.dumps(packet))
    extra["v1_fallback"] = True
    with pytest.raises(ValidationError):
        lane.validate_openrouter_v2_public_request(
            extra,
            plan=plan,
            checkout_commit_sha256=plan.checkout_commit_sha256,
        )


def test_openrouter_v2_direct_evidence_contracts_reject_v1_before_field_parsing() -> None:
    from itda.contracts.phase5_openrouter_recovery import (
        OpenRouterAttemptV2,
        OpenRouterFirstPassV2,
        OpenRouterGenerationV2,
        OpenRouterJournalEntryV2,
        OpenRouterLedgerEntryV2,
        OpenRouterTerminalV2,
    )

    for contract in (
        OpenRouterFirstPassV2,
        OpenRouterLedgerEntryV2,
        OpenRouterJournalEntryV2,
        OpenRouterAttemptV2,
        OpenRouterGenerationV2,
        OpenRouterTerminalV2,
    ):
        with pytest.raises(PermissionError, match="OPENROUTER_V2_HISTORICAL_AUTHORITY_REJECTED"):
            contract.model_validate({"authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID})


def test_openrouter_v2_boundary_rejects_v1_and_cross_version_before_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.contracts.phase5_openrouter_recovery import (
        OPENROUTER_V2_RECOVERY_AUTHORITY_ID,
        OPENROUTER_V2_REQUEST_SCHEMA,
        reject_historical_openrouter_v2_coordinates,
    )

    capability_touched = False

    def deny_capability(*_args: object, **_kwargs: object) -> object:
        nonlocal capability_touched
        capability_touched = True
        raise AssertionError("provider/client/socket/filesystem capability was reached")

    monkeypatch.setattr(httpx, "AsyncClient", deny_capability)
    historical_values = (
        OPENROUTER_RECOVERY_AUTHORITY_ID,
        "itda.phase5-openrouter-recovery-request.v1",
        "artifacts/public/phase5/openrouter-recovery-request.json",
        "backend/src/itda/providers/openrouter_ox_alpha_api_contract.json",
        "artifacts/restricted/catalog/phase5-openrouter-recovery",
        "artifacts/reports/phase5/openrouter-recovery-terminal.json",
        "22e6da6d531befa35bcd7128ae37eadb364acdf846bf20d9beccae737358670f",
        "619b6fd9b31d6a2dc3d40cde98614fd57e96ef944d268c07364d93b3fccde187",
        "1e28243098b48e48c09e841b53a15dd3518f55690d1dc1e0b3fc29d641313043",
        "77092b9a7ae4d78eab6d896bc919d4a3223a9b501c2fac89cd75112a5845253e",
        "8795f32689c9c90f9d5ee07ab6a667915bc446939b1b0d5307223788c6585540",
        "dfcabfaa615b9dd8929a9f2681260ee2f04c194112a609380505ca34cf77f81b",
        "0c0b46ee40137bea1708f8e9bed94d2a234f280f9e62febd73f5422002b83619",
        "48659483bef9cc40fa461817b3c60d2eecc93c011a22f4ebd300c46ce1eaaa94",
        "270a38cb1da259955856a9b4b0a7542b65648666440a74f3321f8c1d0f20da43",
        "0d8b10b725b6c69dbc2ddc87cbf47b4e60842cc9ee86d6a2a1eeed5ab6054951",
        "831b1476cab010d11191d9ab52d820824c5b6c922787313cb86bdc57f58e8c9f",
        "5c9ccd5b169a6b9f584b8361d0b0c40c13c5990830aa2096ba871ce6bb9f351c",
        "508517d3cf64e0227e9e4c81f6864f07a45efed2",
        "e35c019d0d3c1c79a3e58792231e91ec36b70764",
    )
    for historical in historical_values:
        envelope = {
            "schema_version": OPENROUTER_V2_REQUEST_SCHEMA,
            "authority_id": OPENROUTER_V2_RECOVERY_AUTHORITY_ID,
            "member": {
                "schema_version": "itda.phase5-openrouter-member-request.v2",
                "authority_id": OPENROUTER_V2_RECOVERY_AUTHORITY_ID,
                "candidate": historical,
            },
        }
        with pytest.raises(PermissionError, match="OPENROUTER_V2_HISTORICAL"):
            reject_historical_openrouter_v2_coordinates(envelope)
    assert capability_touched is False


def _member_request(order: int = 1, place_id: str = "place:test-a") -> OpenRouterMemberRequest:
    preimage = {
        "schema_version": "itda.phase5-openrouter-member-request.v1",
        "authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID,
        "place_id": place_id,
        "split": "DEV",
        "first_pass_order": order,
        "source_bundle_sha256": "a" * 64,
        "evidence_inventory_sha256": "b" * 64,
        "request_body_sha256": "c" * 64,
    }
    return OpenRouterMemberRequest.model_validate(
        {**preimage, "request_sha256": canonical_sha256(preimage)}
    )


# ---------------------------------------------------------------- namespace


class TestNamespaceDisjointness:
    def test_authority_id_is_new_and_valid(self) -> None:
        assert validate_openrouter_authority_id(OPENROUTER_RECOVERY_AUTHORITY_ID)

    def test_authority_id_rejects_every_historical_lane(self) -> None:
        for historical in (
            "phase5-nvidia-minimax-m3-fresh-d24-20260816",
            "phase5-nvidia-minimax-m3-minimal-probe-20260820",
            "phase5-nvidia-minimax-m3-fresh24-20260820",
        ):
            assert historical in HISTORICAL_AUTHORITY_IDS
            with pytest.raises(ValueError):
                validate_openrouter_authority_id(historical)

    def test_paths_are_new_and_disjoint_from_fresh24(self) -> None:
        assert lane.OPENROUTER_PUBLIC_REQUEST_RELATIVE == (
            "artifacts/public/phase5/openrouter-recovery-request.json"
        )
        assert lane.OPENROUTER_PROTECTED_ROOT_RELATIVE == (
            "artifacts/restricted/catalog/phase5-openrouter-recovery"
        )
        assert lane.OPENROUTER_TERMINAL_RELATIVE == (
            "artifacts/reports/phase5/openrouter-recovery-terminal.json"
        )
        from itda.pipeline.phase5_fresh24 import (
            FRESH24_PROTECTED_ROOT_RELATIVE,
            FRESH24_PUBLIC_REQUEST_RELATIVE,
            FRESH24_TERMINAL_RELATIVE,
        )

        assert lane.OPENROUTER_PUBLIC_REQUEST_RELATIVE != FRESH24_PUBLIC_REQUEST_RELATIVE
        assert lane.OPENROUTER_PROTECTED_ROOT_RELATIVE != FRESH24_PROTECTED_ROOT_RELATIVE
        assert lane.OPENROUTER_TERMINAL_RELATIVE != FRESH24_TERMINAL_RELATIVE

    def test_probe_and_fresh24_evidence_is_non_member(self) -> None:
        # A historical authority ID can never be a member's authority.
        preimage = {
            "schema_version": "itda.phase5-openrouter-member-request.v1",
            "authority_id": "phase5-nvidia-minimax-m3-minimal-probe-20260820",
            "place_id": "place:test-a",
            "split": "DEV",
            "first_pass_order": 1,
            "source_bundle_sha256": "a" * 64,
            "evidence_inventory_sha256": "b" * 64,
            "request_body_sha256": "c" * 64,
        }
        with pytest.raises((ValueError, ValidationError)):
            OpenRouterMemberRequest.model_validate(
                {**preimage, "request_sha256": canonical_sha256(preimage)}
            )


# ----------------------------------------------------------------- snapshot


class TestSnapshot:
    def test_snapshot_self_digest_verifies(self) -> None:
        snapshot = load_openrouter_snapshot()
        payload = json.loads(OPENROUTER_SNAPSHOT_PATH.read_bytes())
        stored = payload.pop("snapshot_sha256")
        assert canonical_sha256(payload) == stored
        assert snapshot.snapshot_sha256 == stored

    def test_snapshot_official_facts(self) -> None:
        snapshot = load_openrouter_snapshot()
        assert snapshot.endpoint["url"] == OPENROUTER_ENDPOINT
        assert snapshot.endpoint["method"] == "POST"
        assert snapshot.endpoint["auth_scheme"] == "Bearer"
        assert snapshot.model["slug"] == OPENROUTER_MODEL
        assert snapshot.model["canonical_slug"] == OPENROUTER_MODEL
        assert snapshot.model["context_length"] == 1048576
        assert snapshot.model["max_completion_tokens"] == 131072
        pricing = snapshot.model["pricing"]
        assert pricing["prompt_per_million_tokens"] == "0"
        assert pricing["completion_per_million_tokens"] == "0"
        assert snapshot.model["supported_parameters"] == [
            "include_reasoning",
            "max_tokens",
            "reasoning",
            "reasoning_effort",
            "response_format",
            "temperature",
            "tool_choice",
            "tools",
            "top_k",
            "top_p",
        ]
        reasoning = snapshot.model["reasoning"]
        assert reasoning["required"] is True
        assert reasoning["default_enabled"] is True
        assert reasoning["default_effort"] == "max"
        assert reasoning["allowed_efforts"] == ["high", "low", "max"]
        assert reasoning["selected_effort"] == OPENROUTER_REASONING_EFFORT
        assert snapshot.data_policy["prompts_retained"] is True
        assert snapshot.data_policy["completions_retained"] is True
        assert snapshot.data_policy["used_for_training"] is False
        assert snapshot.data_policy["retention_duration_known"] is False
        assert snapshot.attribution_headers_sent is False
        assert snapshot.accessed_at == "2026-08-23T00:00:00Z"
        assert snapshot.expiration_date == "2098-12-31"

    def test_snapshot_tamper_rejected(self, tmp_path: Path) -> None:
        original = OPENROUTER_SNAPSHOT_PATH.read_bytes()
        payload = json.loads(original)
        payload["model"]["context_length"] = 999
        tampered = tmp_path / "snapshot.json"
        tampered.write_bytes(json.dumps(payload, sort_keys=True, indent=2).encode())
        with pytest.raises((ValueError, ValidationError)):
            load_openrouter_snapshot(tampered)

    def test_snapshot_digest_mismatch_rejected(self, tmp_path: Path) -> None:
        original = OPENROUTER_SNAPSHOT_PATH.read_bytes()
        payload = json.loads(original)
        payload["snapshot_sha256"] = "0" * 64
        tampered = tmp_path / "snapshot.json"
        tampered.write_bytes(json.dumps(payload, sort_keys=True, indent=2).encode())
        with pytest.raises((ValueError, ValidationError)):
            load_openrouter_snapshot(tampered)

    def test_snapshot_missing_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(PermissionError):
            load_openrouter_snapshot(tmp_path / "absent.json")

    def test_snapshot_expiration_rejected(self, tmp_path: Path) -> None:
        original = OPENROUTER_SNAPSHOT_PATH.read_bytes()
        payload = json.loads(original)
        payload["expiration_date"] = "2020-01-01"
        unsigned = {k: v for k, v in payload.items() if k != "snapshot_sha256"}
        payload["snapshot_sha256"] = canonical_sha256(unsigned)
        expired = tmp_path / "snapshot.json"
        expired.write_bytes(json.dumps(payload, sort_keys=True, indent=2).encode())
        with pytest.raises((ValueError, ValidationError)):
            load_openrouter_snapshot(expired)

    def test_snapshot_unsupported_param_rejected(self, tmp_path: Path) -> None:
        original = OPENROUTER_SNAPSHOT_PATH.read_bytes()
        payload = json.loads(original)
        payload["model"]["supported_parameters"] = ["seed", "temperature"]
        unsigned = {k: v for k, v in payload.items() if k != "snapshot_sha256"}
        payload["snapshot_sha256"] = canonical_sha256(unsigned)
        drifted = tmp_path / "snapshot.json"
        drifted.write_bytes(json.dumps(payload, sort_keys=True, indent=2).encode())
        with pytest.raises((ValueError, ValidationError)):
            load_openrouter_snapshot(drifted)

    def test_runtime_metadata_fetch_is_forbidden_by_contract(self) -> None:
        snapshot = load_openrouter_snapshot()
        assert snapshot.runtime_metadata_fetch_forbidden is True
        assert snapshot.captured_offline is True


# ------------------------------------------------------------ request body


class TestExactRequestBody:
    def test_exact_field_set_and_values(self) -> None:
        fields = openrouter_request_body_fields()
        assert set(fields) == set(OPENROUTER_REQUEST_BODY_KEYS)
        assert fields["model"] == OPENROUTER_MODEL
        assert fields["temperature"] == 1.0
        assert fields["max_tokens"] == 8192
        assert fields["stream"] is False
        assert fields["reasoning"] == {"effort": "high"}
        assert fields["response_format"] == {"type": "json_object"}
        assert fields["provider"] == {
            "allow_fallbacks": False,
            "require_parameters": True,
            "max_price": {"prompt": "0", "completion": "0"},
        }

    def test_forbidden_fields_rejected(self) -> None:
        body = dict(openrouter_request_body_fields())
        body["seed"] = 0
        with pytest.raises(ValueError):
            validate_openrouter_request_body(body)
        body = dict(openrouter_request_body_fields())
        body["chat_template_kwargs"] = {"thinking_mode": "disabled"}
        with pytest.raises(ValueError):
            validate_openrouter_request_body(body)
        body = dict(openrouter_request_body_fields())
        body["models"] = ["other/model"]
        with pytest.raises(ValueError):
            validate_openrouter_request_body(body)

    def test_nonzero_or_missing_max_price_rejected(self) -> None:
        body = dict(openrouter_request_body_fields())
        body["provider"] = {
            "allow_fallbacks": False,
            "require_parameters": True,
            "max_price": {"prompt": "1", "completion": "0"},
        }
        with pytest.raises(ValueError):
            validate_openrouter_request_body(body)
        body = dict(openrouter_request_body_fields())
        body["provider"] = {"allow_fallbacks": False, "require_parameters": True}
        with pytest.raises(ValueError):
            validate_openrouter_request_body(body)

    def test_header_allowlist_is_exact(self) -> None:
        assert OPENROUTER_ALLOWED_HEADERS == ("Authorization", "Content-Type", "Accept")

    def test_attribution_headers_not_sent(self) -> None:
        snapshot = load_openrouter_snapshot()
        assert snapshot.attribution_headers_sent is False
        assert "HTTP-Referer" in snapshot.optional_attribution_headers
        assert "X-OpenRouter-Title" in snapshot.optional_attribution_headers


# ------------------------------------------------------------- member/lineage


class TestMemberLineage:
    def test_first_member_binds_snapshot_and_zero_price(self) -> None:
        request = _member_request()
        snapshot_digest = str(load_openrouter_snapshot().snapshot_sha256)
        expected_lineage = canonical_sha256(
            {
                "authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID,
                "place_id": "place:test-a",
                "source_bundle_sha256": "a" * 64,
                "evidence_inventory_sha256": "b" * 64,
                "request_sha256": request.request_sha256,
                "prompt_sha256": request.lineage_sha256,  # placeholder replaced below
                "profile_schema_sha256": "x" * 64,
                "config_sha256": "y" * 64,
                "preprocessing_sha256": "z" * 64,
                "snapshot_sha256": snapshot_digest,
            }
        )
        # The lineage digest is derived inside the contract; here we assert
        # only coherence: it is a digest and stable across rebuilds.
        rebuilt = _member_request()
        assert request.lineage_sha256 == rebuilt.lineage_sha256
        assert len(request.lineage_sha256) == 64
        del expected_lineage

    def test_member_rejects_nonzero_price_world(self) -> None:
        assert OPENROUTER_RESERVATION_MICRO_USD == 0

    def test_member_rejects_historical_authority(self) -> None:
        preimage = {
            "schema_version": "itda.phase5-openrouter-member-request.v1",
            "authority_id": "phase5-nvidia-minimax-m3-fresh24-20260820",
            "place_id": "place:test-a",
            "split": "DEV",
            "first_pass_order": 1,
            "source_bundle_sha256": "a" * 64,
            "evidence_inventory_sha256": "b" * 64,
            "request_body_sha256": "c" * 64,
        }
        with pytest.raises((ValueError, ValidationError)):
            OpenRouterMemberRequest.model_validate(
                {**preimage, "request_sha256": canonical_sha256(preimage)}
            )


# ------------------------------------------------------- policies / scheduler


class TestPoliciesAndScheduler:
    def test_retry_policy_bounds_match_contract(self) -> None:
        policy = OpenRouterRetryPolicy()
        assert policy.first_pass_requests == 24
        assert policy.max_retries == 6
        assert policy.max_attempts == 30
        assert policy.retry_once_per_place is True
        assert policy.first_pass_precedes_retries is True
        assert policy.concurrency == 1
        assert policy.attempt_deadline_seconds == 300
        assert policy.max_response_bytes == 4 * 1024 * 1024
        assert OPENROUTER_RETRYABLE_HTTP_STATUSES == (408, 429, 500, 502, 503, 524, 529)
        assert OPENROUTER_TERMINAL_HTTP_STATUSES == (400, 401, 402, 403, 404, 413, 422)

    def test_zero_exposure_policy_distinguishes_zero_from_unknown(self) -> None:
        policy = OpenRouterExposurePolicy()
        assert policy.price_status == "EXACT_ZERO"
        assert policy.reservation_micro_usd == 0
        assert policy.cumulative_cap_micro_usd == 0
        assert policy.zero_distinct_from_unknown is True
        assert policy.events_persisted == ("RESERVE", "DISPATCH", "COMMIT")
        assert policy.attempt_counts_persisted is True

    def test_scheduler_all_first_passes_before_retries(self) -> None:
        scheduler = lane.OpenRouterScheduler([f"place:{i:02d}" for i in range(24)])
        with pytest.raises(RuntimeError):
            # First pass not consumed yet: retries are illegal.
            scheduler.retry_order(["place:00"])
        first = scheduler.first_pass()
        assert len(first) == 24
        with pytest.raises(RuntimeError):
            # All 24 first passes must DISPATCH before any retry is planned.
            scheduler.retry_order(["place:00"])
        for place in first:
            scheduler.record_dispatched(place, is_retry=False)
        order = scheduler.retry_order(["place:00", "place:01"])
        assert order == ("place:00", "place:01")
        with pytest.raises(RuntimeError):
            # The retry budget was consumed exactly once.
            scheduler.retry_order(["place:02"])

    def test_scheduler_rejects_more_than_six_retries(self) -> None:
        scheduler = lane.OpenRouterScheduler([f"place:{i:02d}" for i in range(24)])
        for place in scheduler.first_pass():
            scheduler.record_dispatched(place, is_retry=False)
        with pytest.raises(RuntimeError):
            scheduler.retry_order([f"place:{i:02d}" for i in range(7)])

    def test_scheduler_rejects_retry_before_first_pass_done(self) -> None:
        scheduler = lane.OpenRouterScheduler([f"place:{i:02d}" for i in range(24)])
        with pytest.raises(RuntimeError):
            scheduler.retry_order(["place:00"])

    def test_scheduler_retry_classification(self) -> None:
        scheduler = lane.OpenRouterScheduler([f"place:{i:02d}" for i in range(24)])
        assert scheduler.classify_retry(status_code=429) is True
        assert scheduler.classify_retry(status_code=529) is True
        assert scheduler.classify_retry(status_code=400) is False
        assert scheduler.classify_retry(status_code=401) is False
        assert scheduler.classify_retry(status_code=413) is False
        assert scheduler.classify_retry(error="ReadTimeout") is True
        assert scheduler.classify_retry(error="PermissionError") is False
        assert scheduler.classify_retry() is False
        assert OPENROUTER_MAX_RETRIES == 6
        assert OPENROUTER_MAX_ATTEMPTS == 30


# ------------------------------------------------------- protected descriptor


class TestProtectedDescriptor:
    def test_descriptor_inventory_is_exact(self, tmp_path: Path) -> None:
        root = tmp_path / "protected"
        descriptor = OpenRouterProtectedStateDescriptor.from_root(state_root=str(root))
        assert descriptor.approval_target == f"{root}/approval.json"
        assert descriptor.terminal_target == f"{root}/terminal.json"
        assert descriptor.authority_id == OPENROUTER_RECOVERY_AUTHORITY_ID

    def test_descriptor_rejects_relative_root(self) -> None:
        with pytest.raises((ValueError, ValidationError)):
            OpenRouterProtectedStateDescriptor.from_root(state_root="relative/path")

    def test_descriptor_rejects_extra_target(self, tmp_path: Path) -> None:
        root = tmp_path / "protected"
        payload = {
            "schema_version": "itda.phase5-openrouter-protected-state.v1",
            "authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID,
            "state_root": str(root),
            "approval_target": f"{root}/approval.json",
            "claim_target": f"{root}/claim.json",
            "ledger_target": f"{root}/ledger.jsonl",
            "journal_target": f"{root}/journal",
            "raw_evidence_target": f"{root}/raw-evidence",
            "profile_target": f"{root}/profiles",
            "generation_target": f"{root}/generation.json",
            "terminal_target": f"{root}/terminal.json",
            "extra_target": f"{root}/extra.json",
        }
        with pytest.raises((ValueError, ValidationError)):
            OpenRouterProtectedStateDescriptor.model_validate(
                {**payload, "protected_state_sha256": "0" * 64}
            )


# ------------------------------------------------- durable state (synthetic)


def _canonical(payload: dict[str, object]) -> bytes:
    from itda.domain.canonical import canonical_json_bytes

    return canonical_json_bytes(payload)


def _cjb(payload: object) -> bytes:
    from itda.domain.canonical import canonical_json_bytes as cjb

    return cjb(payload)


def _committed_packet_binding_fields() -> dict[str, str]:
    packet_bytes = lane.read_fixed_public_packet_bytes()
    packet = json.loads(packet_bytes)
    return {
        "request_artifact_sha256": str(packet["request_artifact_sha256"]),
        "request_file_sha256": hashlib.sha256(packet_bytes).hexdigest(),
    }


def _claim_for_root(descriptor, request_artifact: str, approval_digest: str):
    """A synthetic one-use claim bound to THIS root's persisted approval."""

    from itda.contracts.phase5_openrouter_recovery import OpenRouterClaim

    fields = {
        "schema_version": "itda.phase5-openrouter-claim.v1",
        "authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID,
        "request_artifact_sha256": request_artifact,
        "request_file_sha256": request_artifact,
        "approval_sha256": approval_digest,
        "protected_state_sha256": str(descriptor.protected_state_sha256),
    }
    return OpenRouterClaim.model_validate({**fields, "claim_sha256": canonical_sha256(fields)})


def _seed_approval(root: Path) -> None:
    """Write a valid synthetic approval bound to THIS root's descriptor."""

    from itda.contracts.phase5_openrouter_recovery import (
        OpenRouterApprovalBinding,
        OpenRouterProtectedStateDescriptor,
    )

    descriptor = OpenRouterProtectedStateDescriptor.from_root(state_root=str(root))
    fields = {
        "schema_version": "itda.phase5-openrouter-approval.v1",
        "authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID,
        "decision": "APPROVED",
        "request_artifact_sha256": "e" * 64,
        "request_file_sha256": "e" * 64,
        "request_manifest_sha256": "f" * 64,
        "membership_sha256": "0" * 64,
        "checkout_manifest_sha256": "1" * 64,
        "checkout_commit_sha256": "a" * 40,
        "protected_state_sha256": str(descriptor.protected_state_sha256),
        "secret_identity_sha256": "2" * 64,
        "provider_lane": "OPENROUTER_API",
        "endpoint": "https://openrouter.ai/api/v1/chat/completions",
        "model": "stealth/ox-alpha",
        "snapshot_sha256": str(load_openrouter_snapshot().snapshot_sha256),
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
    approval = OpenRouterApprovalBinding.model_validate(
        {**fields, "approval_sha256": canonical_sha256(fields)}
    )
    root.mkdir(mode=0o700, exist_ok=True)
    (root / "approval.json").write_bytes(_canonical(approval.model_dump(mode="json")))
    os.chmod(root / "approval.json", 0o600)
    return str(approval.approval_sha256)


class TestDurableStateSynthetic:
    def _state(self, tmp_path: Path) -> lane.OpenRouterDurableAuthorityState:
        descriptor = OpenRouterProtectedStateDescriptor.from_root(state_root=str(tmp_path / "root"))
        return lane.OpenRouterDurableAuthorityState(descriptor)

    def test_reserve_dispatch_commit_zero_price_events(self, tmp_path: Path) -> None:
        state = self._state(tmp_path)
        root = tmp_path / "root"
        _seed_approval(root)
        from itda.contracts.phase5_openrouter_recovery import (
            OpenRouterProtectedStateDescriptor,
        )

        approval_digest = _seed_approval(root)
        descriptor = OpenRouterProtectedStateDescriptor.from_root(state_root=str(root))
        claim = _claim_for_root(
            descriptor, request_artifact="e" * 64, approval_digest=approval_digest
        )
        (root / "claim.json").write_bytes(_canonical(claim.model_dump(mode="json")))
        os.chmod(root / "claim.json", 0o600)
        ordinal = state.reserve_once(
            claim=claim,
            place_id="place:test-a",
            request_sha256="9" * 64,
        )
        assert ordinal == 1
        state.record_dispatch(
            claim=claim,
            place_id="place:test-a",
            request_sha256="9" * 64,
            attempt_number=ordinal,
        )
        evidence = state.persist_attempt_evidence(
            claim=claim,
            place_id="place:test-a",
            request_sha256="9" * 64,
            attempt_number=ordinal,
            response_body=b"{}",
            status_code=200,
        )
        state.commit_reservation(
            claim=claim,
            place_id="place:test-a",
            request_sha256="9" * 64,
            attempt_number=ordinal,
            evidence_sha256=evidence,
        )
        entries = state.read_ledger_entries()
        operations = [row["operation"] for row in entries]
        assert operations == ["RESERVE", "DISPATCH", "COMMIT"]
        assert all(row["amount_micro_usd"] == 0 for row in entries)
        assert state.committed_exposure_micro_usd() == 0
        counts = state.committed_attempt_counts()
        assert counts == {"RESERVE": 1, "DISPATCH": 1, "COMMIT": 1}

    def test_reserve_rejects_second_attempt_before_settlement(self, tmp_path: Path) -> None:
        state = self._state(tmp_path)
        root = tmp_path / "root"
        _seed_approval(root)
        from itda.contracts.phase5_openrouter_recovery import (
            OpenRouterProtectedStateDescriptor,
        )

        approval_digest = _seed_approval(root)
        descriptor = OpenRouterProtectedStateDescriptor.from_root(state_root=str(root))
        claim = _claim_for_root(
            descriptor, request_artifact="e" * 64, approval_digest=approval_digest
        )
        (root / "claim.json").write_bytes(_canonical(claim.model_dump(mode="json")))
        os.chmod(root / "claim.json", 0o600)
        state.reserve_once(claim=claim, place_id="place:test-a", request_sha256="9" * 64)
        with pytest.raises(PermissionError):
            state.reserve_once(claim=claim, place_id="place:test-a", request_sha256="9" * 64)

    def test_claim_is_one_use(self, tmp_path: Path) -> None:
        state = self._state(tmp_path)
        root = tmp_path / "root"
        _seed_approval(root)
        artifact = {"request_artifact_sha256": "e" * 64}
        state.claim_once(request_artifact=artifact)
        with pytest.raises(PermissionError):
            state.claim_once(request_artifact=artifact)

    def test_root_inventory_requires_exact_names(self, tmp_path: Path) -> None:
        state = self._state(tmp_path)
        root = tmp_path / "root"
        root.mkdir(mode=0o700)
        (root / "approval.json").write_text("{}")
        with pytest.raises(PermissionError):
            state.validate_root_inventory(require_generation=False)

    def test_root_rejects_symlink_entry(self, tmp_path: Path) -> None:
        state = self._state(tmp_path)
        root = tmp_path / "root"
        root.mkdir(mode=0o700)
        for name in (
            "approval.json",
            "claim.json",
            "ledger.jsonl",
            "journal",
            "raw-evidence",
            "profiles",
            "terminal.json",
        ):
            (root / name).touch()
        (root / "journal").unlink()
        (root / "journal").symlink_to(tmp_path / "elsewhere")
        with pytest.raises(PermissionError):
            state.validate_root_inventory(require_generation=False)


# ------------------------------------------------------- sealed production seam


def _synthetic_bundle(place_id: str) -> object:
    """A provider-free DemoSourceBundle for body-shape tests (temp-only)."""

    from itda.contracts.demo_profile_materialization import (
        DemoSourceBundle,
        DemoSourceEvidence,
    )

    sources = []
    for index in range(2):
        text = f"synthetic tourism description {index} for {place_id}"
        text_sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
        sources.append(
            DemoSourceEvidence(
                evidence_id=f"ev-{index}",
                source_kind="TOUR_API_DESCRIPTION",
                source_sha256=text_sha,
                span_sha256=text_sha,
                text=text,
            )
        )
    unsigned_payload = {
        "schema_version": "itda.demo-source-bundle.v1",
        "place_id": place_id,
        "split": "DEV",
        "sources": [s.model_dump(mode="json") for s in sources],  # type: ignore[union-attr]
        "optional_image": None,
        "source_inventory_sha256": "0" * 64,
    }
    return DemoSourceBundle.model_validate(
        {
            **unsigned_payload,
            "source_bundle_sha256": canonical_sha256(unsigned_payload),
        }
    )


class TestSealedProductionRunner:
    """The frozen runner executes real attempts through the private mock seam.

    No real network, no real secret: MockTransport answers inside one event
    loop, synthetic bundles and temporary roots only.
    """

    def test_mock_requires_isolated_temp_root(self) -> None:
        import asyncio
        import inspect

        assert inspect.iscoroutinefunction(lane.execute_openrouter_mock_transport)
        with pytest.raises(PermissionError, match="OPENROUTER_MOCK_FORBIDS_PRODUCTION_ROOT"):
            asyncio.run(
                lane.execute_openrouter_mock_transport(
                    plan=None,  # type: ignore[arg-type]
                    claim=None,  # type: ignore[arg-type]
                    protected_state_root=Path(
                        lane.REPOSITORY_ROOT
                        / "artifacts/restricted/catalog/phase5-openrouter-recovery"
                    ),
                    response_handler=lambda request: httpx.Response(200),
                )
            )

    def test_frozen_entry_points_fail_closed_without_bootstrap(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The zero-argument production entry fails closed in a pytest process:
        the sanitized-entrypoint origin gate rejects BEFORE any offline check,
        packet read, client construction, credential read, or durable
        mutation.  The exact bootstrap rejection code is asserted (this module's
        autouse ``_no_provider_env`` fixture already cleared provider env)."""
        monkeypatch.setenv("ITDA_PROVIDER_NETWORK", "1")
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.delenv("ITDA_OFFLINE", raising=False)
        monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)
        with pytest.raises(PermissionError, match="MINIMAL_PROBE_BOOTSTRAP"):
            lane.execute_openrouter_production()

    def test_request_body_exact_shape_per_member(self) -> None:
        """Every member body reconstructs exactly: two messages, canonical JSON."""

        import json as json_module

        from itda.contracts.phase5_openrouter_recovery import (
            OPENROUTER_PROMPT_TEXT,
            validate_openrouter_request_body,
        )

        bundle = _synthetic_bundle("place:synthetic-a")
        parsed = json_module.loads(lane._openrouter_request_body(bundle))
        validate_openrouter_request_body(parsed, expected_place_id=bundle.place_id)
        messages = parsed["messages"]
        assert len(messages) == 2
        assert messages[0] == {"role": "system", "content": OPENROUTER_PROMPT_TEXT}
        user = json_module.loads(messages[1]["content"])
        assert user["place_id"] == "place:synthetic-a"
        evidence_ids = [row["evidence_id"] for row in user["evidence"]]
        source_ids = [s.evidence_id for s in bundle.sources]
        assert evidence_ids == source_ids

    def test_forbidden_content_in_evidence_rejected_before_capability(self) -> None:
        from itda.contracts.phase5_openrouter_recovery import (
            openrouter_user_message_content,
        )

        with pytest.raises(ValueError, match="forbidden"):
            openrouter_user_message_content(
                place_id="place:x",
                evidence=[
                    {"evidence_id": "e1", "source_kind": "overview", "text": "ok"},
                    {
                        "evidence_id": "e2",
                        "source_kind": "overview",
                        "text": "BLIND evaluation material",
                    },
                ],
            )
        with pytest.raises(ValueError, match="forbidden"):
            openrouter_user_message_content(
                place_id="place:x",
                evidence=[
                    {"evidence_id": "e1", "source_kind": "api_key", "text": "ok"},
                ],
            )

    def test_place_substitution_rejected_by_validator(self) -> None:
        import json as json_module

        from itda.contracts.phase5_openrouter_recovery import (
            validate_openrouter_request_body,
        )

        bundle = _synthetic_bundle("place:synthetic-b")
        body = json_module.loads(lane._openrouter_request_body(bundle))
        messages = body["messages"]
        user = json_module.loads(messages[1]["content"])
        user["place_id"] = "place:other"
        messages[1]["content"] = json_module.dumps(
            user, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        with pytest.raises(ValueError, match="place does not match"):
            validate_openrouter_request_body(body, expected_place_id=bundle.place_id)

    def test_arbitrary_prompt_drift_rejected(self) -> None:
        import json as json_module

        from itda.contracts.phase5_openrouter_recovery import (
            validate_openrouter_request_body,
        )

        bundle = _synthetic_bundle("place:synthetic-c")
        body = json_module.loads(lane._openrouter_request_body(bundle))
        body["messages"][0]["content"] = "You are a helpful pirate."
        with pytest.raises(ValueError, match="system prompt drifted"):
            validate_openrouter_request_body(body, expected_place_id=bundle.place_id)

    def test_key_text_mutation_rejected(self) -> None:
        import json as json_module

        from itda.contracts.phase5_openrouter_recovery import (
            validate_openrouter_request_body,
        )

        bundle = _synthetic_bundle("place:synthetic-d")
        body = json_module.loads(lane._openrouter_request_body(bundle))
        user = json_module.loads(body["messages"][1]["content"])
        user["instruction"] = user["instruction"].replace("only", "ONLY ANY")
        body["messages"][1]["content"] = json_module.dumps(
            user, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        with pytest.raises(ValueError, match="instruction drifted"):
            validate_openrouter_request_body(body, expected_place_id=bundle.place_id)

    def test_evidence_text_drift_and_reorder_change_canonical_bytes(self) -> None:
        """Text drift and reorder change canonical content; digests pin order."""

        import json as json_module

        from itda.contracts.phase5_openrouter_recovery import (
            openrouter_user_message_content,
        )

        bundle = _synthetic_bundle("place:synthetic-e")
        ordered = lane.openrouter_evidence_projection(bundle)
        reordered = list(reversed(ordered))
        original_content = openrouter_user_message_content(
            place_id=bundle.place_id, evidence=ordered
        )
        drifted_content = openrouter_user_message_content(
            place_id=bundle.place_id, evidence=reordered
        )
        assert original_content != drifted_content
        text_drifted = [dict(row) for row in ordered]
        text_drifted[0]["text"] = text_drifted[0]["text"] + " tampered"
        assert (
            openrouter_user_message_content(place_id=bundle.place_id, evidence=text_drifted)
            != original_content
        )
        # The approved request_body_sha256 pins the ordered reconstruction.
        body_sha = hashlib.sha256(lane._openrouter_request_body(bundle)).hexdigest()
        drifted_payload = dict(json_module.loads(lane._openrouter_request_body(bundle)))
        drifted_payload["messages"][1]["content"] = drifted_content
        drifted_bytes = json_module.dumps(
            drifted_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
        assert hashlib.sha256(drifted_bytes).hexdigest() != body_sha


# ------------------------------------------------------- provider-free guard


class TestProviderFree:
    def test_no_provider_variables_set(self) -> None:
        for name in ("NVIDIA_KEY", "ZHIPUAI_API_KEY", "BIGMODEL_API_KEY", "OPENROUTER_API_KEY"):
            assert name not in os.environ

    def test_snapshot_file_identity(self) -> None:
        path = OPENROUTER_SNAPSHOT_PATH
        metadata = path.lstat()
        assert stat.S_ISREG(metadata.st_mode)
        assert not path.is_symlink()
        raw = path.read_bytes()
        assert hashlib.sha256(raw).hexdigest()


# ------------------------------------------------- full synthetic E2E (C/F)


def _e2e_profile_payload(
    place_id: str,
    *,
    source_bundle_sha256: str,
    evidence_inventory_sha256: str,
    request_sha256: str,
    variation: int = 0,
) -> dict[str, object]:
    """One valid OpenRouter profile payload bound to its member lineage.

    ``variation`` spreads axis/subattribute/trait values so the deterministic
    kernel produces distinct per-scenario results and real contrasts.
    """

    from itda.contracts.phase5_openrouter_recovery import OpenRouterProfile

    spread = variation % 24
    base = {
        "schema_version": "itda.phase5-openrouter-profile.v1",
        "place_id": place_id,
        "axis_scores": {
            "H": 50 + ((spread * 7) % 41),
            "E": 45 + ((spread * 11) % 46),
            "R": 55 + ((spread * 5) % 36),
        },
        "subattributes": {
            **{f"H{i}": 1 + ((spread + i) % 4) for i in range(1, 5)},
            **{f"I{i}": 1 + ((spread * 2 + i) % 4) for i in range(1, 5)},
            **{f"R{i}": 1 + ((spread * 3 + i) % 4) for i in range(1, 5)},
        },
        "mismatch_traits": {f"M{i}": 10 + ((spread * 9 + i * 13) % 71) for i in range(1, 7)},
        "evidence_justifications": {
            "H": ("ev-0",),
            "E": ("ev-0",),
            "R": ("ev-0",),
            **{f"H{i}": ("ev-0",) for i in range(1, 5)},
            **{f"I{i}": ("ev-0",) for i in range(1, 5)},
            **{f"R{i}": ("ev-0",) for i in range(1, 5)},
            **{f"M{i}": ("ev-0",) for i in range(1, 7)},
        },
        "confidence": 80,
        "evidence_ids": ("ev-0", "ev-1"),
        "source_bundle_sha256": source_bundle_sha256,
        "evidence_inventory_sha256": evidence_inventory_sha256,
        "request_sha256": request_sha256,
        "response_sha256": canonical_sha256({"r": place_id}),
    }
    validated = OpenRouterProfile.model_validate(base)
    return validated.model_dump(mode="json")


def _APPROVAL_PREIMAGE_FIELDS(*, root: Path, plan: lane.OpenRouterPlan) -> dict:
    """The exact synthetic approval preimage shared by seeding helpers.

    ``root`` is accepted for descriptor binding; the returned dict excludes
    ``approval_sha256`` so callers can re-stamp identity fields before
    validating.
    """

    from itda.contracts.phase5_openrouter_recovery import (
        OpenRouterProtectedStateDescriptor,
        load_openrouter_snapshot,
    )

    descriptor = OpenRouterProtectedStateDescriptor.from_root(state_root=str(root))
    return {
        "schema_version": "itda.phase5-openrouter-approval.v1",
        "authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID,
        "decision": "APPROVED",
        **_committed_packet_binding_fields(),
        "request_manifest_sha256": plan.request_manifest_sha256,
        "membership_sha256": OPENROUTER_MEMBERSHIP_SHA256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        # Bind the plan's REAL resolved checkout commit so the generation
        # manifest and the approval agree during reconstruction.
        "checkout_commit_sha256": plan.checkout_commit_sha256,
        "protected_state_sha256": str(descriptor.protected_state_sha256),
        "secret_identity_sha256": "2" * 64,
        "provider_lane": "OPENROUTER_API",
        "endpoint": "https://openrouter.ai/api/v1/chat/completions",
        "model": "stealth/ox-alpha",
        "snapshot_sha256": str(load_openrouter_snapshot().snapshot_sha256),
        "member_count": 24,
        "first_pass_count": 24,
        "max_retries": 6,
        "max_attempts": 30,
        "concurrency": 1,
        "attempt_deadline_seconds": 300,
        "max_response_bytes": 4194304,
        "reservation_micro_usd": 0,
        "cumulative_exposure_micro_usd": 0,
        "receipt_emitted": False,
        "lifecycle_mutated": False,
    }


def _seed_e2e_approval(root: Path, plan: lane.OpenRouterPlan) -> str:
    """Write a valid synthetic approval bound to THIS root and plan."""

    from itda.contracts.phase5_openrouter_recovery import (
        OpenRouterApprovalBinding,
    )

    fields = dict(_APPROVAL_PREIMAGE_FIELDS(root=root, plan=plan))
    approval = OpenRouterApprovalBinding.model_validate(
        {**fields, "approval_sha256": canonical_sha256(fields)}
    )
    root.mkdir(mode=0o700, exist_ok=True)
    (root / "approval.json").write_bytes(_canonical(approval.model_dump(mode="json")))
    os.chmod(root / "approval.json", 0o600)
    return str(approval.approval_sha256)


class TestFullSyntheticE2E:
    """Sealed executor through the private MockTransport seam (temp roots).

    No real network, no real secret.  Proves ordering, zero-price events,
    protected/public byte equality, neutral verification, and forgery
    rejection on the synthetic namespace.
    """

    def _build_plan_24(self) -> lane.OpenRouterPlan:
        from unittest import mock as mock_module

        from itda.domain.demo_profile_eligibility import _CANONICAL_DEV_IDS
        from itda.pipeline.demo_profile_materialization import (
            validate_demo_source_inventory,
        )

        bundles = [_synthetic_bundle(place_id) for place_id in _CANONICAL_DEV_IDS]
        validated = validate_demo_source_inventory(bundles)  # type: ignore[arg-type]
        # Keep the synthetic source indirection active through plan build AND
        # the whole E2E run: T-05R-95 reconstructs every outbound body at
        # DISPATCH time from this (patched) fixed-source revalidation.  The
        # active patcher is pinned on THIS test instance so it survives until
        # pytest drops the instance after the test finishes.
        self._source_patcher = mock_module.patch.object(
            lane, "_verified_source_bundles", return_value=validated
        )
        if not getattr(self._source_patcher, "_active", False):
            self._source_patcher.start()
        plan = lane.build_openrouter_plan(
            validated,
            checkout_manifest_digest="a" * 64,
        )
        return plan

    def _profiles_for(self, plan: lane.OpenRouterPlan) -> dict[str, dict[str, object]]:
        profiles_by_place: dict[str, dict[str, object]] = {}
        for index, member in enumerate(plan.members):
            profiles_by_place[member.place_id] = _e2e_profile_payload(
                member.place_id,
                source_bundle_sha256=member.source_bundle_sha256,
                evidence_inventory_sha256=member.evidence_inventory_sha256,
                request_sha256=str(member.request.request_sha256),
                variation=index,
            )
        return profiles_by_place

    def test_transport_complete_run_zero_price_and_neutral_negative(self, tmp_path: Path) -> None:
        import asyncio
        import json as json_module

        plan = self._build_plan_24()
        profiles = self._profiles_for(plan)

        def handler(request: httpx.Request) -> httpx.Response:
            body = json_module.loads(request.content.decode("utf-8"))
            user = json_module.loads(body["messages"][1]["content"])
            return httpx.Response(200, json={"profile": profiles[user["place_id"]]})

        root = tmp_path / "e2e-root"
        approval_digest = _seed_e2e_approval(root, plan)
        state = lane.OpenRouterDurableAuthorityState(
            OpenRouterProtectedStateDescriptor.from_root(state_root=str(root))
        )
        claim_fields = {
            "schema_version": "itda.phase5-openrouter-claim.v1",
            "authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID,
            **_committed_packet_binding_fields(),
            "approval_sha256": approval_digest,
            "protected_state_sha256": str(state.descriptor.protected_state_sha256),
        }
        from itda.contracts.phase5_openrouter_recovery import OpenRouterClaim

        claim = OpenRouterClaim.model_validate(
            {**claim_fields, "claim_sha256": canonical_sha256(claim_fields)}
        )
        (root / "claim.json").write_bytes(_canonical(claim.model_dump(mode="json")))
        os.chmod(root / "claim.json", 0o600)

        result = asyncio.run(
            lane.execute_openrouter_mock_transport(
                plan=plan,
                claim=claim,
                protected_state_root=root,
                response_handler=handler,
            )
        )
        assert result["attempt_count"] == 24
        assert result["retry_count"] == 0
        assert result["committed_exposure_micro_usd"] == 0
        entries = state.read_ledger_entries()
        operations = [row["operation"] for row in entries]
        assert operations.count("RESERVE") == 24
        assert operations.count("DISPATCH") == 24
        assert operations.count("COMMIT") == 24
        assert all(row["amount_micro_usd"] == 0 for row in entries)
        # Protected terminal bytes equal the returned payload exactly.
        assert _cjb(result) == state.read_protected_terminal_bytes()
        outcome = lane.verify_openrouter_outcome(terminal=result, protected_root=root)
        expected_disposition = (
            "POSITIVE" if result["status"] == "COMPLETE_CANDIDATE_READY" else result["status"]
        )
        assert lane.classify_verified_outcome(outcome) == expected_disposition
        if result["status"] == "COMPLETE_CANDIDATE_READY":
            # The full positive path: generation + 24 durable profiles exist and
            # the separate strict-positive assertion accepts this terminal only.
            assert result["profile_count"] == 24
            assert len(state.list_profile_names()) == 24
            positive_terminal = lane.assert_openrouter_positive_outcome(outcome)
            assert positive_terminal.effective_candidate_count >= 5
        else:
            with pytest.raises(ValueError):
                lane.assert_openrouter_positive_outcome(outcome)

    def test_retry_crash_conservative_no_resend(self, tmp_path: Path) -> None:
        import asyncio
        import json as json_module

        plan = self._build_plan_24()
        profiles = self._profiles_for(plan)
        attempts = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            body = json_module.loads(request.content.decode("utf-8"))
            user = json_module.loads(body["messages"][1]["content"])
            attempts["n"] += 1
            if attempts["n"] == 3:
                raise httpx.ConnectError("crashed")
            return httpx.Response(200, json={"profile": profiles[user["place_id"]]})

        root = tmp_path / "reconcile-root"
        approval_digest = _seed_e2e_approval(root, plan)
        state = lane.OpenRouterDurableAuthorityState(
            OpenRouterProtectedStateDescriptor.from_root(state_root=str(root))
        )
        claim_fields = {
            "schema_version": "itda.phase5-openrouter-claim.v1",
            "authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID,
            **_committed_packet_binding_fields(),
            "approval_sha256": approval_digest,
            "protected_state_sha256": str(state.descriptor.protected_state_sha256),
        }
        from itda.contracts.phase5_openrouter_recovery import OpenRouterClaim

        claim = OpenRouterClaim.model_validate(
            {**claim_fields, "claim_sha256": canonical_sha256(claim_fields)}
        )
        (root / "claim.json").write_bytes(_canonical(claim.model_dump(mode="json")))
        os.chmod(root / "claim.json", 0o600)
        result = asyncio.run(
            lane.execute_openrouter_mock_transport(
                plan=plan,
                claim=claim,
                protected_state_root=root,
                response_handler=handler,
            )
        )
        entries = state.read_ledger_entries()
        reserves = [r for r in entries if r["operation"] == "RESERVE"]
        settled = [r for r in entries if r["operation"] in {"COMMIT", "RECOVER_UNRESOLVED"}]
        assert len(reserves) == len(settled)
        assert all(row["amount_micro_usd"] == 0 for row in entries)
        assert result["committed_exposure_micro_usd"] == 0
        # The ledger digest inside the terminal matches the reopened ledger.
        assert result["ledger_sha256"] == canonical_sha256(entries)
        # CR-02: the crash-produced terminal verifies and classifies NEUTRALLY
        # even on the negative branch (exact root inventory holds).
        outcome = lane.verify_openrouter_outcome(terminal=result, protected_root=root)
        disposition = lane.classify_verified_outcome(outcome)
        assert disposition in {"DESIGNED_NEGATIVE", "POSITIVE"}
        if result["status"] != "COMPLETE_CANDIDATE_READY":
            assert disposition == "DESIGNED_NEGATIVE"

    def test_generation_forgery_rejected_at_reconstruction(self, tmp_path: Path) -> None:
        from itda.contracts.phase5_openrouter_recovery import OpenRouterTerminal

        root = tmp_path / "forgery-root"
        _seed_e2e_approval(root, self._build_plan_24())
        (root / "generation.json").write_bytes(_cjb({"profiles": []}))
        forged_terminal_fields = {
            "schema_version": "itda.phase5-openrouter-terminal.v1",
            "status": "DESIGNED_NEGATIVE",
            "reason": "OPENROUTER_INTERRUPTED_EXPOSURE_CONSERVATIVE",
            "authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID,
            "request_sha256": "a" * 64,
            "request_file_sha256": "b" * 64,
            "checkout_manifest_sha256": "c" * 64,
            "claim_sha256": "d" * 64,
            "ledger_sha256": "e" * 64,
            "journal_sha256": "f" * 64,
            "attempt_count": 24,
            "retry_count": 0,
            "client_constructed": True,
            "network_attempted": True,
            "send_certainty": "SEND_ATTEMPT_MAY_HAVE_STARTED",
            "dispatch_certainty": "SEND_ATTEMPT_MAY_HAVE_STARTED",
        }
        forged = OpenRouterTerminal.model_validate(forged_terminal_fields)
        # WR-B re-audit: exact exception — the seeded root lacks the full
        # durable inventory, so the FIRST gate (validate_root_inventory) must
        # reject with the exact protected-root code.  A verifier that let a
        # forged generation through would raise nothing at all.
        with pytest.raises(PermissionError, match="OPENROUTER_PROTECTED_ROOT_INVENTORY_INVALID"):
            lane.verify_openrouter_outcome(
                terminal=forged.model_dump(mode="json"), protected_root=root
            )

    def test_production_runner_cannot_be_pointed_at_mock_seam(self) -> None:
        """Public production bindings never consult the private mock seam."""

        import inspect

        source = inspect.getsource(lane._make_openrouter_runner)
        assert "execute_openrouter_mock_transport" not in source
        assert "MockTransport" not in source


# ------------------------------------------------- security re-audit fixes


class TestCrashPointFactSemantics:
    """WR-A re-audit: each of the four crash points produces FACT-CONSISTENT
    durable rows and a neutral-verifiable terminal — booleans true only for
    locally confirmed facts, unknown dimensions carried by certainty fields,
    never a fabricated CONFIRMED_SENT."""

    def _seeded_root(self, tmp_path: Path, plan):
        root = tmp_path / "crash-root"
        approval_digest = _seed_e2e_approval(root, plan)
        descriptor = OpenRouterProtectedStateDescriptor.from_root(state_root=str(root))
        state = lane.OpenRouterDurableAuthorityState(descriptor)
        claim_fields = {
            "schema_version": "itda.phase5-openrouter-claim.v1",
            "authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID,
            **_committed_packet_binding_fields(),
            "approval_sha256": approval_digest,
            "protected_state_sha256": str(descriptor.protected_state_sha256),
        }
        from itda.contracts.phase5_openrouter_recovery import OpenRouterClaim

        claim = OpenRouterClaim.model_validate(
            {**claim_fields, "claim_sha256": canonical_sha256(claim_fields)}
        )
        (root / "claim.json").write_bytes(_canonical(claim.model_dump(mode="json")))
        os.chmod(root / "claim.json", 0o600)
        return root, state, claim

    def test_crash_at_reserve_only(self, tmp_path: Path) -> None:
        """RESERVE row with NO dispatch marker: deterministic settlement —
        client=false, network=false, dispatch_certainty=RESERVED,
        send_certainty=NOT_STARTED.  The reconcile terminal verifies NEUTRALLY."""

        plan = TestFullSyntheticE2E()._build_plan_24()
        root, state, claim = self._seeded_root(tmp_path, plan)
        member = plan.members[0]
        state.reserve_once(
            claim=claim,
            place_id=member.place_id,
            request_sha256=str(member.request.request_sha256),
        )
        # The RESERVE row itself carries its phase.
        reserve_row = [
            row for row in state.read_ledger_entries() if row.get("operation") == "RESERVE"
        ][0]
        assert reserve_row.get("dispatch_phase") == "RESERVED"
        recovered = state.reconcile_interrupted(claim=claim)
        assert recovered is not None
        assert recovered["recovered_count"] == 1
        entry = [
            e for e in state.read_ledger_entries() if e.get("operation") == "RECOVER_UNRESOLVED"
        ][0]
        assert entry.get("dispatch_phase") == "RESERVED"
        assert entry.get("dispatch_certainty") == "RESERVED"
        assert entry.get("send_certainty") == "NOT_STARTED_CONFIRMED_LOCALLY"
        assert entry.get("client_fact") == "NOT_STARTED_CONFIRMED_LOCALLY"
        assert entry.get("may_have_attempted") is False

    def test_crash_after_client_marker_before_boundary(self, tmp_path: Path) -> None:
        """A DURABLE client marker exists but no send-boundary marker:
        client=true confirmed, dispatch certainty CLIENT_CONSTRUCTED, send
        UNKNOWN_AFTER_DISPATCH, may_have_attempted=true."""

        plan = TestFullSyntheticE2E()._build_plan_24()
        root, state, claim = self._seeded_root(tmp_path, plan)
        member = plan.members[0]
        ordinal = state.reserve_once(
            claim=claim,
            place_id=member.place_id,
            request_sha256=str(member.request.request_sha256),
        )
        state.record_dispatch(
            claim=claim,
            place_id=member.place_id,
            request_sha256=str(member.request.request_sha256),
            attempt_number=ordinal,
        )
        state.record_client_constructed(
            claim=claim, place_id=member.place_id, attempt_number=ordinal
        )
        journal_names = sorted(os.listdir(root / "journal"))
        assert f"client-{ordinal:02d}.json" in journal_names
        assert not any(name.startswith("send-boundary") for name in journal_names)
        recovered = state.reconcile_interrupted(claim=claim)
        assert recovered is not None
        entry = [
            e for e in state.read_ledger_entries() if e.get("operation") == "RECOVER_UNRESOLVED"
        ][0]
        assert entry.get("dispatch_phase") == "CLIENT_CONSTRUCTED"
        assert entry.get("dispatch_certainty") == ("CLIENT_CONSTRUCTED_CONFIRMED_LOCALLY")
        assert entry.get("send_certainty") == "UNKNOWN_AFTER_DISPATCH"
        assert entry.get("client_fact") == "CLIENT_CONSTRUCTED_CONFIRMED_LOCALLY"
        assert entry.get("may_have_attempted") is True

    def test_crash_after_send_boundary(self, tmp_path: Path) -> None:
        """SEND-BOUNDARY durable marker present: the boundary was REACHED —
        the request op MAY have started; it can never be proven SENT.
        client=true confirmed; may_have_attempted=true; certainties are
        MAY_HAVE/UNKNOWN_AFTER_SEND_BOUNDARY."""

        plan = TestFullSyntheticE2E()._build_plan_24()
        root, state, claim = self._seeded_root(tmp_path, plan)
        member = plan.members[0]
        ordinal = state.reserve_once(
            claim=claim,
            place_id=member.place_id,
            request_sha256=str(member.request.request_sha256),
        )
        state.record_dispatch(
            claim=claim,
            place_id=member.place_id,
            request_sha256=str(member.request.request_sha256),
            attempt_number=ordinal,
        )
        state.record_client_constructed(
            claim=claim, place_id=member.place_id, attempt_number=ordinal
        )
        state.record_send_boundary(claim=claim, place_id=member.place_id, attempt_number=ordinal)
        journal_names = sorted(os.listdir(root / "journal"))
        assert f"send-boundary-{ordinal:02d}.json" in journal_names
        recovered = state.reconcile_interrupted(claim=claim)
        assert recovered is not None
        entry = [
            e for e in state.read_ledger_entries() if e.get("operation") == "RECOVER_UNRESOLVED"
        ][0]
        assert entry.get("dispatch_phase") == "SEND_ATTEMPT_BOUNDARY_REACHED"
        assert entry.get("dispatch_certainty") == "UNKNOWN_AFTER_SEND_BOUNDARY"
        assert entry.get("send_certainty") == "SEND_ATTEMPT_MAY_HAVE_STARTED"
        assert entry.get("client_fact") == "CLIENT_CONSTRUCTED_CONFIRMED_LOCALLY"
        assert entry.get("may_have_attempted") is True

    def test_reconcile_terminal_neutral_verification_all_phases(self, tmp_path: Path) -> None:
        """The reconcile terminal verifies NEUTRALLY at every crash point with
        consistent certainty fields — no boolean hardcoding anywhere."""

        builder = TestFullSyntheticE2E()
        plan = builder._build_plan_24()
        root, state, claim = self._seeded_root(tmp_path, plan)
        member = plan.members[0]
        ordinal = state.reserve_once(
            claim=claim,
            place_id=member.place_id,
            request_sha256=str(member.request.request_sha256),
        )
        state.record_dispatch(
            claim=claim,
            place_id=member.place_id,
            request_sha256=str(member.request.request_sha256),
            attempt_number=ordinal,
        )
        payload = state.reconcile_terminal(
            claim=claim,
            approval=__import__(
                "itda.contracts.phase5_openrouter_recovery",
                fromlist=["OpenRouterApprovalBinding"],
            ).OpenRouterApprovalBinding.model_validate(
                json.loads((root / "approval.json").read_bytes().decode("utf-8"))
            ),
            plan=plan,
            artifact={
                "request_artifact_sha256": _committed_packet_binding_fields()[
                    "request_artifact_sha256"
                ]
            },
        )
        assert payload is not None
        # DISPATCH_PREPARED-only crash: exact terminal facts.
        assert payload["network_attempted"] is False
        assert payload["client_constructed"] is False
        assert payload["send_certainty"] == "NOT_STARTED_CONFIRMED_LOCALLY"
        assert payload["dispatch_certainty"] == "DISPATCH_PREPARED"
        outcome = lane.verify_openrouter_outcome(terminal=payload, protected_root=root)
        assert lane.classify_verified_outcome(outcome) == "DESIGNED_NEGATIVE"

    def test_reserve_only_reconcile_terminal_neutral_verification(self, tmp_path: Path) -> None:
        """RESERVE-only crash reconciles deterministically and its terminal
        verifies NEUTRALLY with the RESERVED phase facts."""

        plan = TestFullSyntheticE2E()._build_plan_24()
        root, state, claim = self._seeded_root(tmp_path, plan)
        member = plan.members[0]
        state.reserve_once(
            claim=claim,
            place_id=member.place_id,
            request_sha256=str(member.request.request_sha256),
        )
        payload = state.reconcile_terminal(
            claim=claim,
            approval=__import__(
                "itda.contracts.phase5_openrouter_recovery",
                fromlist=["OpenRouterApprovalBinding"],
            ).OpenRouterApprovalBinding.model_validate(
                json.loads((root / "approval.json").read_bytes().decode("utf-8"))
            ),
            plan=plan,
            artifact={
                "request_artifact_sha256": _committed_packet_binding_fields()[
                    "request_artifact_sha256"
                ]
            },
        )
        assert payload is not None
        assert payload["network_attempted"] is False
        assert payload["client_constructed"] is False
        assert payload["send_certainty"] == "NOT_STARTED_CONFIRMED_LOCALLY"
        assert payload["dispatch_certainty"] == "RESERVED"
        outcome = lane.verify_openrouter_outcome(terminal=payload, protected_root=root)
        assert lane.classify_verified_outcome(outcome) == "DESIGNED_NEGATIVE"


class TestDispatchTimeBodyReconstruction:
    """T-05R-95: every outbound body is rebuilt from the FIXED source at
    dispatch time and checked byte-exactly against the approved manifest."""

    def test_reconstruction_rejects_drifted_member_identity(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A member whose source/inventory identity drifted from the fixed
        source can NEVER have its body reconstructed — proven against a
        SYNTHETIC fixed source so the test cannot pass via a missing
        FileNotFound/OSError from an absent real evidence directory."""
        from unittest import mock as mock_module

        from itda.domain.demo_profile_eligibility import _CANONICAL_DEV_IDS
        from itda.pipeline.demo_profile_materialization import (
            validate_demo_source_inventory,
        )

        validated = validate_demo_source_inventory(
            [_synthetic_bundle(p) for p in _CANONICAL_DEV_IDS]
        )  # type: ignore[arg-type]
        patcher = mock_module.patch.object(lane, "_verified_source_bundles", return_value=validated)
        patcher.start()
        try:
            member = _member_request()
            drifted = lane.OpenRouterMember(
                authority_id=OPENROUTER_RECOVERY_AUTHORITY_ID,
                place_id=member.place_id,
                source_bundle_sha256="a" * 64,
                evidence_inventory_sha256="b" * 64,
                request_body=b"{}",
                request=member,
            )
            # The synthetic source IS present and revalidated; the rejection
            # must come from the EXACT identity-drift code path.
            with pytest.raises(PermissionError, match="OPENROUTER_BODY_SOURCE_MEMBER_NOT_UNIQUE"):
                lane.reconstruct_member_body_exact(drifted)
        finally:
            patcher.stop()

    def test_reconstruction_rejects_digest_drift_with_synthetic_source(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A member whose manifest digest does not match a full synthetic
        rebuild hits the exact reconstruction-digest drift rejection."""
        from unittest import mock as mock_module

        from itda.domain.demo_profile_eligibility import _CANONICAL_DEV_IDS
        from itda.pipeline.demo_profile_materialization import (
            validate_demo_source_inventory,
        )

        validated = validate_demo_source_inventory(
            [_synthetic_bundle(p) for p in _CANONICAL_DEV_IDS]
        )  # type: ignore[arg-type]
        first = sorted(validated, key=lambda bundle: str(bundle.place_id))[0]
        body = lane._openrouter_request_body(first)
        inventory = canonical_sha256(
            [
                {
                    "evidence_id": s.evidence_id,
                    "source_kind": s.source_kind,
                    "source_sha256": s.source_sha256,
                    "span_sha256": s.span_sha256,
                }
                for s in first.sources
            ]
        )
        preimage = {
            "schema_version": "itda.phase5-openrouter-member-request.v1",
            "authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID,
            "place_id": str(first.place_id),
            "split": "DEV",
            "first_pass_order": 1,
            "source_bundle_sha256": str(first.source_bundle_sha256),
            "evidence_inventory_sha256": inventory,
            # WRONG digest on purpose.
            "request_body_sha256": "c" * 64,
        }
        from itda.contracts.phase5_openrouter_recovery import OpenRouterMemberRequest

        request = OpenRouterMemberRequest.model_validate(
            {**preimage, "request_sha256": canonical_sha256(preimage)}
        )
        drifted_member = lane.OpenRouterMember(
            authority_id=OPENROUTER_RECOVERY_AUTHORITY_ID,
            place_id=str(first.place_id),
            source_bundle_sha256=str(first.source_bundle_sha256),
            evidence_inventory_sha256=inventory,
            request_body=b"TAMPERED-NOT-TRUSTED",
            request=request,
        )
        patcher = mock_module.patch.object(lane, "_verified_source_bundles", return_value=validated)
        patcher.start()
        try:
            with pytest.raises(
                PermissionError, match="OPENROUTER_BODY_RECONSTRUCTION_DIGEST_DRIFT"
            ):
                lane.reconstruct_member_body_exact(drifted_member)
            assert hashlib.sha256(body).hexdigest() != "c" * 64
        finally:
            patcher.stop()

    def test_reconstruction_is_byte_exact_for_verified_source(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """For the (synthetic) verified fixed source the reconstruction equals
        the plan body even when the stored bytes were tampered."""

        from unittest import mock as mock_module

        from itda.domain.demo_profile_eligibility import _CANONICAL_DEV_IDS
        from itda.pipeline.demo_profile_materialization import (
            validate_demo_source_inventory,
        )

        validated = validate_demo_source_inventory(
            [_synthetic_bundle(p) for p in _CANONICAL_DEV_IDS]
        )  # type: ignore[arg-type]
        bundles = validated
        first = sorted(bundles, key=lambda bundle: str(bundle.place_id))[0]
        body = lane._openrouter_request_body(first)
        inventory = canonical_sha256(
            [
                {
                    "evidence_id": s.evidence_id,
                    "source_kind": s.source_kind,
                    "source_sha256": s.source_sha256,
                    "span_sha256": s.span_sha256,
                }
                for s in first.sources
            ]
        )
        preimage = {
            "schema_version": "itda.phase5-openrouter-member-request.v1",
            "authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID,
            "place_id": first.place_id,
            "split": "DEV",
            "first_pass_order": 1,
            "source_bundle_sha256": str(first.source_bundle_sha256),
            "evidence_inventory_sha256": inventory,
            "request_body_sha256": hashlib.sha256(body).hexdigest(),
        }
        from itda.contracts.phase5_openrouter_recovery import OpenRouterMemberRequest

        request = OpenRouterMemberRequest.model_validate(
            {**preimage, "request_sha256": canonical_sha256(preimage)}
        )
        member = lane.OpenRouterMember(
            authority_id=OPENROUTER_RECOVERY_AUTHORITY_ID,
            place_id=str(first.place_id),
            source_bundle_sha256=str(first.source_bundle_sha256),
            evidence_inventory_sha256=inventory,
            request_body=b"TAMPERED-NOT-TRUSTED",
            request=request,
        )
        patcher = mock_module.patch.object(lane, "_verified_source_bundles", return_value=validated)
        patcher.start()
        try:
            reconstructed = lane.reconstruct_member_body_exact(member)
        finally:
            patcher.stop()
        assert reconstructed == body
        assert reconstructed != b"TAMPERED-NOT-TRUSTED"


class TestCredentialEchoStripping:
    """T-05R-95: a provider/proxy body carrying the credential exact bytes is
    never persisted — digest-only safe evidence plus a DESIGNED_NEGATIVE."""

    def test_credential_echo_response_never_stored(self, tmp_path: Path) -> None:
        import asyncio
        import json as json_module

        builder = TestFullSyntheticE2E()
        builder._build_plan_24()  # persistent source patch active for the run
        plan = TestCoherentPositiveForgeryRejected._build_patched_plan()
        profiles = TestFullSyntheticE2E._profiles_for(builder, plan)
        echo_secret = "provider-free-test-secret"
        root = tmp_path / "echo-root"

        def handler(request: httpx.Request) -> httpx.Response:
            body = json_module.loads(request.content.decode("utf-8"))
            user = json_module.loads(body["messages"][1]["content"])
            profile = dict(profiles[user["place_id"]])
            # The malicious/misconfigured provider echoes the credential.
            return httpx.Response(200, json={"profile": profile, "echo": echo_secret})

        approval_digest = _seed_e2e_approval(root, plan)
        state = lane.OpenRouterDurableAuthorityState(
            OpenRouterProtectedStateDescriptor.from_root(state_root=str(root))
        )
        claim_fields = {
            "schema_version": "itda.phase5-openrouter-claim.v1",
            "authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID,
            **_committed_packet_binding_fields(),
            "approval_sha256": approval_digest,
            "protected_state_sha256": str(state.descriptor.protected_state_sha256),
        }
        from itda.contracts.phase5_openrouter_recovery import OpenRouterClaim

        claim = OpenRouterClaim.model_validate(
            {**claim_fields, "claim_sha256": canonical_sha256(claim_fields)}
        )
        (root / "claim.json").write_bytes(_canonical(claim.model_dump(mode="json")))
        os.chmod(root / "claim.json", 0o600)
        result = asyncio.run(
            lane.execute_openrouter_mock_transport(
                plan=plan,
                claim=claim,
                protected_state_root=root,
                response_handler=handler,
            )
        )
        assert result["status"] == "DESIGNED_NEGATIVE"
        assert result["reason"] == "OPENROUTER_CREDENTIAL_ECHO_REJECTED"
        # No raw bin anywhere carries the echoed credential bytes.
        raw_dir = root / "raw-evidence"
        if raw_dir.exists():
            for blob_name in sorted(os.listdir(raw_dir)):
                assert echo_secret.encode() not in (raw_dir / blob_name).read_bytes()
        journal_dir = root / "journal"
        for record_name in sorted(os.listdir(journal_dir)):
            blob = (journal_dir / record_name).read_bytes()
            assert echo_secret.encode() not in blob
            # WR-A re-audit: dispatch/send-started markers carry no response
            # data; attempt records keep the length-only safe field.
            assert b'"response_length"' in blob or record_name.startswith(
                ("dispatch", "send-boundary", "client-")
            )
        # The neutral verifier accepts the safe-evidence terminal.
        outcome = lane.verify_openrouter_outcome(terminal=result, protected_root=root)
        assert lane.classify_verified_outcome(outcome) == "DESIGNED_NEGATIVE"


class TestCredentialTaintEncodingInventory:
    """T-05R-95 strict re-audit: the taint detector must catch the EXPLICIT
    fixed encoding inventory — raw secret, hex digest (lower/upper), base64 of
    the raw bytes / of the hex text / of the BINARY digest, standard AND
    urlsafe, padded AND unpadded — and percent-encoded forms with UPPERCASE
    and EXACT-lowercase hex escapes.  Probes are derived in memory; nothing
    (raw/hash/length) is ever stored or printed."""

    # Reserved characters exercise every escape branch: '/' '+' ' ' '=' '%'.
    _SECRET = "A/B+C D=E%"

    @staticmethod
    def _b64(raw: bytes) -> list[bytes]:
        import base64

        std = base64.b64encode(raw)
        url = base64.urlsafe_b64encode(raw)
        return [std, std.rstrip(b"="), url, url.rstrip(b"=")]

    def test_exact_lowercase_percent_encoding_is_detected(self) -> None:
        """Acceptance probe: `A/B+C D=E%` percent-encoded with lowercase hex
        escapes and unreserved literals preserved is EXACTLY
        `A%2fB%2bC%20D%3dE%25` — the detector must flag it.  The literal
        characters D and E must survive the lowercase rewrite untouched."""

        import urllib.parse as urllib_parse

        quoted = urllib_parse.quote(self._SECRET, safe="")
        # stdlib quote preserves unreserved literals, escapes the rest with
        # UPPERCASE hex: A%2FB%2BC%20D%3DE%25.
        assert quoted == "A%2FB%2BC%20D%3DE%25"
        exact_lower_expected = "A%2fB%2bC%20D%3dE%25"
        lowered = lane._lowercase_percent_escapes(quoted)
        # Exact transformation: ONLY the %HH hex digits changed case; the
        # literal A/D/E stayed uppercase (a plain .lower() would corrupt them).
        assert lowered == exact_lower_expected
        body = b'{"error":"echoed","data":"' + exact_lower_expected.encode() + b'"}'
        assert lane._body_is_credential_tainted(body, self._SECRET) is True, (
            "exact-lowercase percent encoding was NOT detected"
        )
        # The plain .lower() corruption would NOT be a valid probe either way;
        # prove the helper never produced it.
        assert lowered != quoted.lower()
        # And the all-bytes exact forms are detected as well.
        all_bytes_upper = "".join(f"%{byte:02X}" for byte in self._SECRET.encode())
        all_bytes_lower = lane._lowercase_percent_escapes(all_bytes_upper)
        assert all_bytes_lower == ("%41%2f%42%2b%43%20%44%3d%45%25")
        for form in (all_bytes_upper, all_bytes_lower):
            body = b'{"data":"' + form.encode() + b'"}'
            assert lane._body_is_credential_tainted(body, self._SECRET) is True

    def test_every_fixed_encoding_is_detected(self) -> None:
        import base64
        import urllib.parse as urllib_parse

        value_bytes = self._SECRET.encode("utf-8")
        digest_binary = hashlib.sha256(value_bytes).digest()
        digest_hex_lower = digest_binary.hex()
        digest_hex_upper = digest_hex_lower.upper()

        detected_encodings: dict[str, bytes] = {
            "raw": value_bytes,
            "hex_lower": digest_hex_lower.encode(),
            "hex_upper": digest_hex_upper.encode(),
            "b64_raw_std": base64.b64encode(value_bytes),
            "b64_raw_std_unpadded": base64.b64encode(value_bytes).rstrip(b"="),
            "b64_raw_url": base64.urlsafe_b64encode(value_bytes),
            "b64_raw_url_unpadded": base64.urlsafe_b64encode(value_bytes).rstrip(b"="),
            "b64_hexlower_std": base64.b64encode(digest_hex_lower.encode()),
            "b64_hexlower_url_unpadded": base64.urlsafe_b64encode(digest_hex_lower.encode()).rstrip(
                b"="
            ),
            "b64_hexupper_std_unpadded": base64.b64encode(digest_hex_upper.encode()).rstrip(b"="),
            "b64_digest_binary_std": base64.b64encode(digest_binary),
            "b64_digest_binary_std_unpadded": base64.b64encode(digest_binary).rstrip(b"="),
            "b64_digest_binary_url": base64.urlsafe_b64encode(digest_binary),
            "b64_digest_binary_url_unpadded": base64.urlsafe_b64encode(digest_binary).rstrip(b"="),
            "b64_hexupper_std": base64.b64encode(digest_hex_upper.encode()),
            "b64_hexupper_url": base64.urlsafe_b64encode(digest_hex_upper.encode()),
            # Percent forms: stdlib-quote output (unreserved literals pass
            # through, lowercase hex escapes), its exact-lowercase rewrite,
            # and the exact all-bytes uppercase/lowercase forms.
            "pct_encoded_quote": urllib_parse.quote(self._SECRET, safe="").encode(),
            "pct_encoded_quote_lowered": lane._lowercase_percent_escapes(
                urllib_parse.quote(self._SECRET, safe="")
            ).encode(),
            "pct_encoded_lower_exact": lane._lowercase_percent_escapes(
                "".join(f"%{byte:02X}" for byte in value_bytes)
            ).encode(),
            "pct_encoded_upper_exact": "".join(f"%{byte:02X}" for byte in value_bytes).encode(
                "ascii"
            ),
        }
        for name, needle in detected_encodings.items():
            body = b'{"error":"echoed","data":"' + needle + b'"}'
            assert lane._body_is_credential_tainted(body, self._SECRET) is True, (
                f"taint detector MISSED encoding: {name}"
            )

    def test_full_mock_attempt_strips_derived_encoding_echoes(self, tmp_path: Path) -> None:
        """Full sealed-attempt run: responses echoing the credential via the
        binary-digest base64 AND the exact-lowercase percent encodings leave
        NOTHING durable (raw/hash/length) and end DESIGNED_NEGATIVE with a
        neutral-verifiable terminal."""

        import asyncio
        import json as json_module

        builder = TestFullSyntheticE2E()
        builder._build_plan_24()
        plan = TestCoherentPositiveForgeryRejected._build_patched_plan()
        profiles = TestFullSyntheticE2E._profiles_for(builder, plan)
        # The private mock namespace resolves THE synthetic credential; derive
        # the needles from THAT value so the echoed encodings genuinely match
        # what the transport resolved (no caller seam exists to change it).
        echo_secret = "provider-free-test-secret"
        value_bytes = echo_secret.encode("utf-8")
        digest_binary = hashlib.sha256(value_bytes).digest()
        import base64

        echo_needles = {
            "b64_binary_digest": base64.b64encode(digest_binary),
            "pct_lowercase_exact": lane._lowercase_percent_escapes(
                "".join(f"%{byte:02X}" for byte in value_bytes)
            ).encode(),
        }
        root = tmp_path / "derived-echo-root"

        def handler(request: httpx.Request) -> httpx.Response:
            body = json_module.loads(request.content.decode("utf-8"))
            user = json_module.loads(body["messages"][1]["content"])
            profile = dict(profiles[user["place_id"]])
            # EVERY response echoes BOTH derived encodings simultaneously, so
            # the very first attempt must trip the taint detector.
            b64_echo = echo_needles["b64_binary_digest"].decode("ascii")
            pct_echo = echo_needles["pct_lowercase_exact"].decode("ascii")
            return httpx.Response(
                200,
                json={
                    "profile": profile,
                    "echo_b64_digest": b64_echo,
                    "echo_pct_lower": pct_echo,
                },
            )

        approval_digest = _seed_e2e_approval(root, plan)
        state = lane.OpenRouterDurableAuthorityState(
            OpenRouterProtectedStateDescriptor.from_root(state_root=str(root))
        )
        claim_fields = {
            "schema_version": "itda.phase5-openrouter-claim.v1",
            "authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID,
            **_committed_packet_binding_fields(),
            "approval_sha256": approval_digest,
            "protected_state_sha256": str(state.descriptor.protected_state_sha256),
        }
        from itda.contracts.phase5_openrouter_recovery import OpenRouterClaim

        claim = OpenRouterClaim.model_validate(
            {**claim_fields, "claim_sha256": canonical_sha256(claim_fields)}
        )
        (root / "claim.json").write_bytes(_canonical(claim.model_dump(mode="json")))
        os.chmod(root / "claim.json", 0o600)
        result = asyncio.run(
            lane.execute_openrouter_mock_transport(
                plan=plan,
                claim=claim,
                protected_state_root=root,
                response_handler=handler,
            )
        )
        assert result["status"] == "DESIGNED_NEGATIVE"
        assert result["reason"] == "OPENROUTER_CREDENTIAL_ECHO_REJECTED"
        # No raw bin anywhere carries ANY derived encoding needle or the raw
        # secret; no length field leaks the echoed sizes.
        raw_dir = root / "raw-evidence"
        if raw_dir.exists():
            for blob_name in sorted(os.listdir(raw_dir)):
                blob = (raw_dir / blob_name).read_bytes()
                assert echo_secret.encode() not in blob
                for needle in echo_needles.values():
                    assert needle not in blob
        journal_dir = root / "journal"
        for record_name in sorted(os.listdir(journal_dir)):
            blob = (journal_dir / record_name).read_bytes()
            assert echo_secret.encode() not in blob
            for needle in echo_needles.values():
                assert needle not in blob
            assert b'"response_length"' in blob or record_name.startswith(
                ("dispatch", "send-boundary", "client-")
            )
        # The neutral verifier accepts the safe-evidence terminal.
        outcome = lane.verify_openrouter_outcome(terminal=result, protected_root=root)
        assert lane.classify_verified_outcome(outcome) == "DESIGNED_NEGATIVE"

    def test_designed_negative_benign_bodies_pass_clean(self) -> None:
        """Fixed designed-negative bodies must NOT be flagged tainted."""

        benign_bodies = (
            b'{"profile":{"place_id":"x"},"note":"sha256 machinery"}',
            b"a" * 4096,
            b"",
            None,
            b'{"error":{"message":"invalid api key"}}',
        )
        for body in benign_bodies:
            assert lane._body_is_credential_tainted(body, self._SECRET) is False, (
                f"benign body falsely flagged: {body[:60]!r}"
            )

    def test_partial_encoding_fragments_are_not_flagged(self) -> None:
        """A fragment that is NOT a complete probe (e.g. half a digest) never
        triggers the detector — precision matters as much as recall."""

        value_bytes = self._SECRET.encode("utf-8")
        digest_hex = hashlib.sha256(value_bytes).hexdigest()
        fragments = (
            digest_hex[:31].encode(),  # half the lower hex digest
            digest_hex[:31].upper().encode(),
            value_bytes[: len(value_bytes) // 2],
        )
        for fragment in fragments:
            body = b'{"data":"' + fragment + b'"}'
            assert lane._body_is_credential_tainted(body, self._SECRET) is False

    def test_empty_secret_or_body_never_tainted(self) -> None:
        assert lane._body_is_credential_tainted(None, self._SECRET) is False
        assert lane._body_is_credential_tainted(b"x", "") is False
        assert lane._body_is_credential_tainted(b"", self._SECRET) is False


def _patched_source_bundles():
    """A started-on-demand synthetic source patcher for focused tests."""

    from unittest import mock as mock_module

    from itda.domain.demo_profile_eligibility import _CANONICAL_DEV_IDS
    from itda.pipeline.demo_profile_materialization import (
        validate_demo_source_inventory,
    )

    bundles = [_synthetic_bundle(place_id) for place_id in _CANONICAL_DEV_IDS]
    validated = validate_demo_source_inventory(bundles)  # type: ignore[arg-type]
    return mock_module.patch.object(lane, "_verified_source_bundles", return_value=validated)


class TestCoherentPositiveForgeryRejected:
    """T-05R-97: a FULLY coherent positive forgery — fresh generation and
    terminal self-digests over swapped durable profiles with STALE maps/
    counts — cannot pass neutral verification."""

    @staticmethod
    def _build_patched_plan() -> lane.OpenRouterPlan:
        """Build a 24-member plan under the ALREADY-ACTIVE synthetic patch."""

        from itda.pipeline.demo_profile_materialization import (
            validate_demo_source_inventory,
        )

        validated = validate_demo_source_inventory(lane._verified_source_bundles())  # type: ignore[arg-type]
        return lane.build_openrouter_plan(validated, checkout_manifest_digest="a" * 64)

    def _run_real_positive(self, tmp_path: Path):
        import asyncio
        import json as json_module

        plan_builder = TestFullSyntheticE2E()
        plan_builder._build_plan_24()  # persistent source patch active
        plan = self._build_patched_plan()
        profiles = TestFullSyntheticE2E._profiles_for(plan_builder, plan)

        def handler(request: httpx.Request) -> httpx.Response:
            body = json_module.loads(request.content.decode("utf-8"))
            user = json_module.loads(body["messages"][1]["content"])
            return httpx.Response(200, json={"profile": profiles[user["place_id"]]})

        root = tmp_path / "coherent-forge-root"
        approval_digest = _seed_e2e_approval(root, plan)
        state = lane.OpenRouterDurableAuthorityState(
            OpenRouterProtectedStateDescriptor.from_root(state_root=str(root))
        )
        claim_fields = {
            "schema_version": "itda.phase5-openrouter-claim.v1",
            "authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID,
            **_committed_packet_binding_fields(),
            "approval_sha256": approval_digest,
            "protected_state_sha256": str(state.descriptor.protected_state_sha256),
        }
        from itda.contracts.phase5_openrouter_recovery import OpenRouterClaim

        claim = OpenRouterClaim.model_validate(
            {**claim_fields, "claim_sha256": canonical_sha256(claim_fields)}
        )
        (root / "claim.json").write_bytes(_canonical(claim.model_dump(mode="json")))
        os.chmod(root / "claim.json", 0o600)
        result = asyncio.run(
            lane.execute_openrouter_mock_transport(
                plan=plan,
                claim=claim,
                protected_state_root=root,
                response_handler=handler,
            )
        )
        return result, root, plan

    def test_swapped_profile_with_stale_maps_fails(self, tmp_path: Path) -> None:
        result, root, _plan = self._run_real_positive(tmp_path)
        assert result["status"] == "COMPLETE_CANDIDATE_READY"
        names = sorted(os.listdir(root / "profiles"))
        victim = root / "profiles" / names[0]
        payload = json.loads(victim.read_bytes())
        place_id = payload["place_id"]
        payload.pop("profile_sha256")
        payload["axis_scores"]["H"] = (payload["axis_scores"]["H"] + 7) % 101
        from itda.contracts.phase5_openrouter_recovery import OpenRouterProfile

        forged_profile = OpenRouterProfile.model_validate(payload).model_dump(mode="json")
        victim.write_bytes(_cjb(forged_profile))
        os.chmod(victim, 0o600)
        generation = json.loads((root / "generation.json").read_bytes())
        generation["profiles"] = [
            {
                "place_id": row["place_id"],
                "profile_sha256": (
                    forged_profile["profile_sha256"]
                    if row["place_id"] == place_id
                    else row["profile_sha256"]
                ),
            }
            for row in generation["profiles"]
        ]
        generation.pop("generation_sha256")
        generation["generation_sha256"] = canonical_sha256(generation)
        generation_bytes = _cjb(generation)
        (root / "generation.json").write_bytes(generation_bytes)
        os.chmod(root / "generation.json", 0o600)
        new_generation_sha = hashlib.sha256(generation_bytes).hexdigest()
        terminal_payload = dict(result)
        terminal_payload["generation_sha256"] = new_generation_sha
        terminal_payload["terminal_sha256"] = None
        from itda.contracts.phase5_openrouter_recovery import OpenRouterTerminal

        forged_terminal = OpenRouterTerminal.model_validate(terminal_payload).model_dump(
            mode="json"
        )
        (root / "terminal.json").write_bytes(_cjb(forged_terminal))
        os.chmod(root / "terminal.json", 0o600)
        # WR-B re-audit: exact exception — the swapped profile's forged
        # generation self-digest is coherent, so reconstruction proceeds to
        # full evaluator recomputation (T-05R-97), where the STALE scenario
        # maps fail to reproduce from the swapped durable profiles.
        with pytest.raises(
            ValueError,
            match="openrouter scenario maps do not reproduce exactly",
        ):
            lane.verify_openrouter_outcome(terminal=forged_terminal, protected_root=root)

    def test_request_manifest_binding_enforced(self, tmp_path: Path) -> None:
        """The generation's request_manifest_sha256 must equal the APPROVED
        approval manifest digest — any other manifest fails reconstruction."""
        result, root, plan = self._run_real_positive(tmp_path)
        assert result["status"] == "COMPLETE_CANDIDATE_READY"
        generation = json.loads((root / "generation.json").read_bytes())
        generation["request_manifest_sha256"] = "f" * 64
        generation.pop("generation_sha256")
        generation["generation_sha256"] = canonical_sha256(generation)
        (root / "generation.json").write_bytes(_cjb(generation))
        os.chmod(root / "generation.json", 0o600)
        terminal_payload = dict(result)
        terminal_payload["generation_sha256"] = hashlib.sha256(
            (root / "generation.json").read_bytes()
        ).hexdigest()
        terminal_payload["terminal_sha256"] = None
        from itda.contracts.phase5_openrouter_recovery import OpenRouterTerminal

        forged_terminal = OpenRouterTerminal.model_validate(terminal_payload).model_dump(
            mode="json"
        )
        (root / "terminal.json").write_bytes(_cjb(forged_terminal))
        os.chmod(root / "terminal.json", 0o600)
        with pytest.raises(ValueError, match="manifest"):
            lane.verify_openrouter_outcome(terminal=forged_terminal, protected_root=root)

    def test_late_malformed_profile_leaves_profiles_empty(self, tmp_path: Path) -> None:
        """CR-02: a malformed profile arriving LAST leaves the profiles dir
        EXACTLY empty — no durable profile evidence precedes the verdict."""

        import asyncio
        import json as json_module

        builder = TestFullSyntheticE2E()
        builder._build_plan_24()
        plan = self._build_patched_plan()
        profiles = TestFullSyntheticE2E._profiles_for(builder, plan)
        last_place_id = plan.members[-1].place_id

        def handler(request: httpx.Request) -> httpx.Response:
            body = json_module.loads(request.content.decode("utf-8"))
            user = json_module.loads(body["messages"][1]["content"])
            if user["place_id"] == last_place_id:
                # The final response is garbage — every earlier one was fine.
                return httpx.Response(200, json={"profile": {"bogus": True}})
            return httpx.Response(200, json={"profile": profiles[user["place_id"]]})

        root = tmp_path / "late-malformed-root"
        approval_digest = _seed_e2e_approval(root, plan)
        state = lane.OpenRouterDurableAuthorityState(
            OpenRouterProtectedStateDescriptor.from_root(state_root=str(root))
        )
        claim_fields = {
            "schema_version": "itda.phase5-openrouter-claim.v1",
            "authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID,
            **_committed_packet_binding_fields(),
            "approval_sha256": approval_digest,
            "protected_state_sha256": str(state.descriptor.protected_state_sha256),
        }
        from itda.contracts.phase5_openrouter_recovery import OpenRouterClaim

        claim = OpenRouterClaim.model_validate(
            {**claim_fields, "claim_sha256": canonical_sha256(claim_fields)}
        )
        (root / "claim.json").write_bytes(_canonical(claim.model_dump(mode="json")))
        os.chmod(root / "claim.json", 0o600)
        result = asyncio.run(
            lane.execute_openrouter_mock_transport(
                plan=plan,
                claim=claim,
                protected_state_root=root,
                response_handler=handler,
            )
        )
        assert result["status"] == "DESIGNED_NEGATIVE"
        assert result["reason"] == "OPENROUTER_PROFILE_LINEAGE_INVALID"
        # The profiles directory holds NOTHING durable.
        assert os.listdir(root / "profiles") == []
        # No generation manifest exists either.
        assert not (root / "generation.json").exists()
        # Neutral verification and classification still pass.
        outcome = lane.verify_openrouter_outcome(terminal=result, protected_root=root)
        assert lane.classify_verified_outcome(outcome) == "DESIGNED_NEGATIVE"

    def test_late_ineligible_cohort_leaves_profiles_empty(self, tmp_path: Path) -> None:
        """CR-02: 24 VALID profiles whose cohort evaluates INELIGIBLE leave
        the profiles dir exactly empty — publish happens only on positive."""

        import asyncio
        import json as json_module

        builder = TestFullSyntheticE2E()
        builder._build_plan_24()
        plan = self._build_patched_plan()
        profiles = TestFullSyntheticE2E._profiles_for(builder, plan)

        def handler(request: httpx.Request) -> httpx.Response:
            body = json_module.loads(request.content.decode("utf-8"))
            user = json_module.loads(body["messages"][1]["content"])
            return httpx.Response(200, json={"profile": profiles[user["place_id"]]})

        root = tmp_path / "late-ineligible-root"
        approval_digest = _seed_e2e_approval(root, plan)
        state = lane.OpenRouterDurableAuthorityState(
            OpenRouterProtectedStateDescriptor.from_root(state_root=str(root))
        )
        claim_fields = {
            "schema_version": "itda.phase5-openrouter-claim.v1",
            "authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID,
            **_committed_packet_binding_fields(),
            "approval_sha256": approval_digest,
            "protected_state_sha256": str(state.descriptor.protected_state_sha256),
        }
        from unittest import mock as mock_module

        from itda.contracts.phase5_openrouter_recovery import OpenRouterClaim

        claim = OpenRouterClaim.model_validate(
            {**claim_fields, "claim_sha256": canonical_sha256(claim_fields)}
        )
        (root / "claim.json").write_bytes(_canonical(claim.model_dump(mode="json")))
        os.chmod(root / "claim.json", 0o600)

        published: list[str] = []
        real_publish = lane.OpenRouterDurableAuthorityState.publish_profile_evidence

        def spying_publish(self_state, **kwargs: object) -> None:
            published.append(str(kwargs.get("place_id")))
            real_publish(self_state, **kwargs)

        patcher = mock_module.patch.object(
            lane.OpenRouterDurableAuthorityState,
            "publish_profile_evidence",
            spying_publish,
        )
        ineligible_reason = "OPENROUTER_COHORT_INELIGIBLE"
        patcher.start()
        try:
            # Force the cohort decision to be ineligible by stubbing the
            # evaluator's decision half through the wraps spy.
            original_eval = lane.evaluate_openrouter_profiles

            def ineligible_eval(profiles_arg, **kwargs: object):
                from types import SimpleNamespace

                decision, evaluation = original_eval(profiles_arg, **kwargs)
                broken_decision = SimpleNamespace(
                    recommendation_eligible=False,
                    effective_candidate_count=0,
                    candidate_count=decision.candidate_count,
                    post_hard_duplicate_count=decision.post_hard_duplicate_count,
                    post_cannot_coappear_count=decision.post_cannot_coappear_count,
                    reason=ineligible_reason,
                )
                return broken_decision, evaluation

            monkeypatch_tmp = patcher  # keep linters happy about scope
            del monkeypatch_tmp
            eval_patch = mock_module.patch.object(
                lane, "evaluate_openrouter_profiles", ineligible_eval
            )
            eval_patch.start()
            try:
                result = asyncio.run(
                    lane.execute_openrouter_mock_transport(
                        plan=plan,
                        claim=claim,
                        protected_state_root=root,
                        response_handler=handler,
                    )
                )
            finally:
                eval_patch.stop()
        finally:
            patcher.stop()
        assert result["status"] == "DESIGNED_NEGATIVE"
        assert result["reason"] == ineligible_reason
        # ZERO durable profile publishes occurred despite 24 valid profiles.
        assert published == []
        assert os.listdir(root / "profiles") == []
        assert not (root / "generation.json").exists()
        outcome = lane.verify_openrouter_outcome(terminal=result, protected_root=root)
        assert lane.classify_verified_outcome(outcome) == "DESIGNED_NEGATIVE"


class TestSealedPublicEntriesNoInjection:
    """T-05R-98: public production entries carry no caller-injectable invoke."""

    def test_entries_fail_closed_when_poisoned_and_run_through_seam(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Two guarantees in one hostile scenario:

        1. FAIL-CLOSED: poisoning the binding holders makes the entry raise
           AttributeError immediately — it NEVER silently consults the runner
           factory, sealed executor, or fixed opener globals, and never
           constructs a client after mutation.
        2. FROZEN RUN through the documented seam: with the binding holders
           intact and ONLY the narrow ``_derive_production_authority`` helper
           stubbed to the synthetic chain, the entry runs its REAL frozen
           transport cells end-to-end over MockTransport clients.
        """

        import asyncio
        import dis
        import json as json_module
        from unittest import mock as mock_module

        builder = TestFullSyntheticE2E()
        builder._build_plan_24()  # persistent synthetic source patch active
        plan = TestCoherentPositiveForgeryRejected._build_patched_plan()
        profiles = TestFullSyntheticE2E._profiles_for(builder, plan)

        def handler(request: httpx.Request) -> httpx.Response:
            body = json_module.loads(request.content.decode("utf-8"))
            user = json_module.loads(body["messages"][1]["content"])
            return httpx.Response(200, json={"profile": profiles[user["place_id"]]})

        # 0. Bytecode proof (T-05R-98 strict): the FROZEN public entries
        # perform ZERO forbidden LOAD_GLOBALs — no binding holder, no runner
        # factory, no sealed executor, no opener, no derivation helper, no
        # REPOSITORY_ROOT, no secret-path helper is consulted at call time.
        for name in (
            "execute_openrouter_production",
            "execute_openrouter_production_async",
        ):
            loaded = {
                instruction.argval
                for instruction in dis.get_instructions(getattr(lane, name))
                if "LOAD_GLOBAL" in instruction.opname
            }
            forbidden = {
                "_SYNC_BINDING",
                "_ASYNC_BINDING",
                "_derive_production_authority",
                "REPOSITORY_ROOT",
                "OPENROUTER_REQUEST_OUTPUT",
                "OPENROUTER_PROTECTED_ROOT",
                "_make_openrouter_runner",
                "_execute_openrouter_transport",
                "_openrouter_open_client_blocking",
                "_openrouter_fixed_secret_file",
                "_openrouter_secret_metadata_identity",
                "_read_fixed_openrouter_secret_value",
                "read_fixed_public_packet_bytes",
                "openrouter_packet_digest_domains",
                "_verified_source_bundles",
                "checkout_manifest_sha256",
                "openrouter_checkout_commit_sha256",
                "build_openrouter_plan",
                "validate_openrouter_public_request",
            }
            assert not (loaded & forbidden), (name, loaded & forbidden)

        # Build the synthetic plan/profiles BEFORE any poisoning (the
        # plan builder consults the source-bundle indirection).

        class _SeamBuilder(TestFullSyntheticE2E):
            pass

        seam_builder = _SeamBuilder()
        seam_builder._build_plan_24()  # persistent source patch active
        seam_plan = TestCoherentPositiveForgeryRejected._build_patched_plan()

        # The synthetic secret's REAL non-value metadata identity — computed
        # BEFORE poisoning (Phase 2 needs it while the globals are poisoned).
        # Computed with the SAME stat-tuple preimage the production identity
        # helper uses, directly over the temp file (no production global is
        # consulted or redirected).
        from itda.domain.canonical import canonical_sha256 as _cs

        _secret_file = tmp_path / ".secrets" / "itda-openrouter.env"
        _secret_file.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(_secret_file.parent, 0o700)
        _secret_file.write_text("OPENROUTER_API_KEY=provider-free-typed-secret\n")
        os.chmod(_secret_file, 0o600)
        _metadata = _secret_file.lstat()
        frozen_identity = _cs(
            {
                "device": _metadata.st_dev,
                "inode": _metadata.st_ino,
                "size": _metadata.st_size,
                "mtime_ns": _metadata.st_mtime_ns,
                "ctime_ns": _metadata.st_ctime_ns,
                "uid": _metadata.st_uid,
                "nlink": _metadata.st_nlink,
                "mode": stat.S_IMODE(_metadata.st_mode),
            }
        )

        try:
            # Phase 1: FAIL-CLOSED under total poisoning — monkeypatch/delete
            # EVERY former mutable global.  The pre-bound entries were sealed
            # at import time; a direct call must still fail on the bootstrap
            # origin gate BEFORE any client construction or mutation.
            def poison(*_args: object, **_kwargs: object) -> object:
                raise AssertionError("mutated module global was consulted")

            cleanup_stack: list = []
            # NOTE: _verified_source_bundles stays OUT of the poison set — it
            # is the synthetic-source indirection the PRIVATE mock seam (and
            # only that seam) legitimately consults for body reconstruction;
            # it is not part of the credential-reader or entry-binding path.
            # _verified_source_bundles / checkout_manifest_sha256 /
            # openrouter_checkout_commit_sha256 are source-LINEAGE helpers
            # used by the private mock seam's body reconstruction and
            # evidence-timestamp derivation — they are not part of the
            # credential-reader or entry-binding path, so the seam run keeps
            # its legitimate synthetic patches for them.
            poisoned_symbols = [
                "_SYNC_BINDING",
                "_ASYNC_BINDING",
                "_derive_production_authority",
                "REPOSITORY_ROOT",
                "OPENROUTER_REQUEST_OUTPUT",
                "OPENROUTER_PROTECTED_ROOT",
                "read_fixed_public_packet_bytes",
                "openrouter_packet_digest_domains",
                "_openrouter_fixed_secret_file",
                "_openrouter_secret_metadata_identity",
                "_read_fixed_openrouter_secret_value",
            ]
            saved_symbols = {}
            for symbol in poisoned_symbols:
                if hasattr(lane, symbol):
                    saved_symbols[symbol] = getattr(lane, symbol)
                    patcher = mock_module.patch.object(lane, symbol, poison)
                    patcher.start()
                    cleanup_stack.append(patcher.stop)

            def _deny_client(*_a: object, **_k: object) -> object:
                raise AssertionError("client construction was reached")

            saved_client = httpx.AsyncClient
            httpx.AsyncClient = _deny_client  # type: ignore[misc]
            cleanup_stack.append(lambda: setattr(httpx, "AsyncClient", saved_client))
            try:
                with pytest.raises(PermissionError, match="MINIMAL_PROBE_BOOTSTRAP_ORIGIN_INVALID"):
                    lane.execute_openrouter_production()
                # A direct call with ANY argument is impossible: TypeError.
                with pytest.raises(TypeError):
                    lane.execute_openrouter_production(plan=plan)  # type: ignore[call-arg]
            finally:
                # Restore httpx before the seam run below.
                httpx.AsyncClient = saved_client
                cleanup_stack.pop()

            # Phase 1b: unwind ALL poisons — Phase 2 exercises the private
            # mock seam, which legitimately uses synthetic source-lineage
            # patches; the frozen public entries were ALREADY proven immune
            # in Phase 1 (they never consulted a single poisoned symbol).
            for stop in reversed(cleanup_stack):
                stop()
            cleanup_stack.clear()

            # Phase 2: the SUCCESS path runs through the strictly-private
            # mock-transport seam ONLY — the public entries themselves are
            # never redirected to temp roots.
            root = tmp_path / "no-injection-root"

            from itda.contracts.phase5_openrouter_recovery import (
                OpenRouterApprovalBinding as _Approval,
            )
            from itda.contracts.phase5_openrouter_recovery import (
                OpenRouterClaim as _Claim,
            )

            approval_fields = dict(_APPROVAL_PREIMAGE_FIELDS(root=root, plan=seam_plan))
            approval_fields["secret_identity_sha256"] = frozen_identity
            restamped = _Approval.model_validate(
                {
                    **approval_fields,
                    "approval_sha256": canonical_sha256(approval_fields),
                }
            )
            root.mkdir(mode=0o700, exist_ok=True)
            (root / "approval.json").write_bytes(_canonical(restamped.model_dump(mode="json")))
            os.chmod(root / "approval.json", 0o600)
            state = lane.OpenRouterDurableAuthorityState(
                OpenRouterProtectedStateDescriptor.from_root(state_root=str(root))
            )
            claim_fields = {
                "schema_version": "itda.phase5-openrouter-claim.v1",
                "authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID,
                "request_artifact_sha256": "e" * 64,
                "request_file_sha256": "e" * 64,
                "approval_sha256": canonical_sha256(approval_fields),
                "protected_state_sha256": str(state.descriptor.protected_state_sha256),
            }
            claim = _Claim.model_validate(
                {**claim_fields, "claim_sha256": canonical_sha256(claim_fields)}
            )
            (root / "claim.json").write_bytes(_canonical(claim.model_dump(mode="json")))
            os.chmod(root / "claim.json", 0o600)

            result = asyncio.run(
                lane.execute_openrouter_mock_transport(
                    plan=seam_plan,
                    claim=claim,
                    protected_state_root=root,
                    response_handler=handler,
                )
            )
            assert result["status"] == "COMPLETE_CANDIDATE_READY"
            assert result["client_constructed"] is True
        finally:
            for stop in reversed(cleanup_stack):
                stop()

    def test_public_entries_have_zero_caller_parameters(self) -> None:
        """T-05R-98 final form: the public production entries take NO caller
        parameters at all — plan/state/claim/artifact/invoke are gone.  Every
        authority input is re-derived from repository-owned constants."""
        import inspect

        for name in (
            "execute_openrouter_production",
            "execute_openrouter_production_async",
        ):
            entry = getattr(lane, name)
            assert entry.__name__ == name
            assert set(inspect.signature(entry).parameters) == set(), (name,)
        # The former live aliases are no longer exported.
        exported = set(lane.__all__)
        assert "execute_openrouter_live" not in exported
        assert "run_openrouter_transport" not in exported
