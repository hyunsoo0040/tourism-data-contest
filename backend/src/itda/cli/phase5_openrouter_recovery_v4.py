"""Provider-free OpenRouter r4/v4 CLI: public commands and sealed dispatch.

Public surface (provider-free, reachable through
``python -m itda.cli.materialize_phase5_demo_profiles`` delegation or direct
module invocation):

- ``openrouter-recovery-v4-preflight``   — packet/snapshot/source preflight.
- ``openrouter-recovery-v4-secret-shape`` — fixed-path secret SHAPE check;
  pass/named-error only; never a value/length/prefix/digest/identity.
- ``openrouter-recovery-v4-verify``      — neutral verification reopening
  every persisted evidence class independently (``--require-positive`` is
  the separate strict-positive step).
- ``openrouter-recovery-v4-classify``    — disposition over verified outcomes.

Capability surface (install/live/reconcile) is bootstrap-only: the public
main rejects those names fail-closed; only the sanitized stdlib bootstrap
entrypoint may route them through :func:`v4_capability_dispatch`.

The production live runner is a zero-argument import-time sealed closure
over fixed paths/builder/reader/client constructor.  Caller root/path/
runner/client/credential injection does not exist on this surface.  The
strictly test-only transport seam remains in the pipeline module's mock
namespace and never aliases production coordinates.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from contextlib import suppress
from pathlib import Path

from itda.cli.freeze_preview import _rename_noreplace_at
from itda.contracts.phase5_openrouter_recovery_v4_paths import (
    OPENROUTER_V4_PROTECTED_ROOT,
    OPENROUTER_V4_PUBLIC_REQUEST_PATH,
    OPENROUTER_V4_TERMINAL_OUTPUT,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]

V4_SECRET_FILE_RELATIVE = ".secrets/itda-openrouter.env"
V4_SECRET_ENV_KEY = "OPENROUTER_API_KEY"
V4_PUBLIC_COMMANDS = (
    "openrouter-recovery-v4-preflight",
    "openrouter-recovery-v4-secret-shape",
    "openrouter-recovery-v4-verify",
    "openrouter-recovery-v4-classify",
)
V4_CAPABILITY_COMMANDS = (
    "openrouter-recovery-v4-install-approval",
    "openrouter-recovery-v4-live",
    "openrouter-recovery-v4-reconcile",
)

_USE_BOOTSTRAP_MESSAGE = "USE_OPENROUTER_V4_BOOTSTRAP_ENTRYPOINT"

# Test-only isolated-root markers shared with the pipeline mock seam.
_V4_TEST_ROOT_MARKERS = ("/tmp/", "/private/tmp/", "/var/folders/")


def build_public_parser() -> argparse.ArgumentParser:
    """The provider-free public parser; capability names are absent."""

    parser = argparse.ArgumentParser(
        prog="itda.cli.phase5_openrouter_recovery_v4",
        description="provider-free openrouter r4/v4 recovery commands",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name in V4_PUBLIC_COMMANDS:
        sub = commands.add_parser(name)
        if name == "openrouter-recovery-v4-preflight":
            sub.add_argument("--request", type=Path, required=True)
            sub.add_argument("--require-committed-clean-source", action="store_true")
            sub.add_argument("--verify-only", action="store_true")
            sub.add_argument("--json", action="store_true")
        elif name == "openrouter-recovery-v4-secret-shape":
            sub.add_argument("--secret-env-file", type=Path, required=True)
            sub.add_argument("--quiet", action="store_true")
        elif name == "openrouter-recovery-v4-verify":
            sub.add_argument("--terminal", type=Path, required=True)
            sub.add_argument("--require-positive", action="store_true")
            sub.add_argument("--json", action="store_true")
        else:
            sub.add_argument("--terminal", type=Path, required=True)
            sub.add_argument("--value-only", action="store_true")
            sub.add_argument("--json", action="store_true")
    return parser


def _print_payload(payload: dict[str, object], *, json_output: bool) -> None:
    from itda.domain.canonical import canonical_json_bytes

    if json_output:
        sys.stdout.buffer.write(canonical_json_bytes(payload) + b"\n")
    else:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))


# ---------------------------------------------------------------------------
# Fixed lexical path resolution — no caller-selected coordinates.
# ---------------------------------------------------------------------------


def _resolve_fixed(path: Path, expected: Path, label: str) -> Path:
    candidate = path if path.is_absolute() else REPOSITORY_ROOT / path
    normalized = Path(os.path.abspath(os.fspath(candidate)))
    if normalized != expected or any(part in {"", ".", ".."} for part in normalized.parts[1:]):
        raise PermissionError(f"caller-selected {label} is forbidden")
    return normalized


def _fixed_terminal_path(path: Path) -> Path:
    return _resolve_fixed(path, OPENROUTER_V4_TERMINAL_OUTPUT, "v4 terminal")


def _fixed_secret_path(path: Path) -> Path:
    expected = REPOSITORY_ROOT / V4_SECRET_FILE_RELATIVE
    resolved = (path if path.is_absolute() else REPOSITORY_ROOT / path).resolve(strict=False)
    if (
        resolved != expected
        or any(part in {"", ".", ".."} for part in resolved.parts[1:])
        or resolved.parent.name != ".secrets"
    ):
        raise PermissionError("caller-selected v4 secret file is forbidden")
    return resolved


# ---------------------------------------------------------------------------
# Secret shape validation — pass / named error only, never value-derived.
# ---------------------------------------------------------------------------


def _inspect_v4_secret(
    path: Path, *, read_content: bool = True
) -> tuple[dict[str, object], str | None]:
    def fail(code: str) -> tuple[dict[str, object], None]:
        return {"status": "fail", "error": code}, None

    if not path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts[1:]):
        return fail("PATH_INVALID")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        parent_fd = os.open(path.anchor, directory_flags)
        for component in path.parts[1:-1]:
            child_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = child_fd
    except OSError:
        if "parent_fd" in locals():
            os.close(parent_fd)
        return fail("PARENT_UNREADABLE")
    try:
        directory_metadata = os.fstat(parent_fd)
        if not stat.S_ISDIR(directory_metadata.st_mode):
            return fail("PARENT_NOT_DIRECTORY")
        if stat.S_IMODE(directory_metadata.st_mode) != 0o700:
            return fail("DIRECTORY_MODE_UNSAFE")
        if directory_metadata.st_uid != os.getuid():
            return fail("DIRECTORY_OWNER_UNSAFE")
        try:
            descriptor = os.open(
                path.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_fd,
            )
        except OSError:
            return fail("NOT_REGULAR_FILE")
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                return fail("NOT_REGULAR_FILE")
            if before.st_nlink != 1:
                return fail("MULTIPLE_LINKS_FORBIDDEN")
            if before.st_uid != os.getuid():
                return fail("OWNER_UNSAFE")
            if stat.S_IMODE(before.st_mode) != 0o600:
                return fail("FILE_MODE_UNSAFE")
            if not 0 < before.st_size <= 64 * 1024:
                return fail("SIZE_OUT_OF_CONTRACT")
            raw = os.read(descriptor, before.st_size + 1) if read_content else b""
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_fd)
    if (read_content and len(raw) != before.st_size) or (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_uid,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_uid,
        after.st_size,
        after.st_mtime_ns,
    ):
        return fail("PATH_CHANGED_DURING_VALIDATION")
    if not read_content:
        return {"status": "pass"}, None
    try:
        text = raw.decode("utf-8").removesuffix("\n")
    except UnicodeDecodeError:
        return fail("ENCODING_INVALID")
    if "\n" in text or "\r" in text or "=" not in text:
        return fail("RECORD_INVALID")
    key, value = text.split("=", 1)
    if key != V4_SECRET_ENV_KEY or not value.strip():
        return fail("RECORD_INVALID")
    return {"status": "pass"}, value


def validate_v4_secret_shape(path: Path) -> dict[str, object]:
    """Return only a named shape result, never secret-derived metadata."""

    result, _value = _inspect_v4_secret(path)
    return result


def validate_v4_secret_metadata(path: Path) -> dict[str, object]:
    """Validate descriptor metadata without reading or decoding file content."""

    result, _value = _inspect_v4_secret(path, read_content=False)
    return result


# ---------------------------------------------------------------------------
# Neutral verified outcome + classifier + strict positive assertion.
# ---------------------------------------------------------------------------


class OpenRouterVerifiedOutcomeV4:
    __slots__ = ("terminal",)

    terminal: object


def classify_openrouter_v4_outcome(
    *, protected_state_root: Path, public_terminal_bytes: bytes
) -> str:
    outcome = verify_openrouter_v4_outcome(
        protected_state_root=protected_state_root,
        public_terminal_bytes=public_terminal_bytes,
    )
    status = getattr(outcome.terminal, "status", None)
    if status == "COMPLETE_CANDIDATE_READY":
        return "POSITIVE"
    if status == "DESIGNED_NEGATIVE":
        return "DESIGNED_NEGATIVE"
    if status == "FAILED_UNACTIVATED":
        return "FAILED_UNACTIVATED"
    raise ValueError("OPENROUTER_V4_DISPOSITION_UNKNOWN")


def assert_openrouter_v4_positive(
    *, protected_state_root: Path, public_terminal_bytes: bytes
) -> None:
    outcome = verify_openrouter_v4_outcome(
        protected_state_root=protected_state_root,
        public_terminal_bytes=public_terminal_bytes,
    )
    if getattr(outcome.terminal, "status", None) != "COMPLETE_CANDIDATE_READY":
        raise ValueError("OPENROUTER_V4_NOT_STRICT_POSITIVE")


# ---------------------------------------------------------------------------
# Neutral verification: independent reopen/reconstruct of persisted evidence.
# ---------------------------------------------------------------------------


def verify_openrouter_v4_outcome(
    *, protected_state_root: Path, public_terminal_bytes: bytes
) -> OpenRouterVerifiedOutcomeV4:
    """Reopen EVERY persisted evidence class independently.

    Reconstructed classes: approval, claim, segmented ledger (chain +
    self-digests), journal markers, outcome counts, raw-evidence lineage,
    reconciliation rows, profile inventory, generation binding (positive
    branch), and the protected terminal bytes.  Malformed or inconsistent
    evidence raises; nothing here reads a secret, constructs a client,
    opens a socket, or touches the production protected root unless invoked
    against exactly that fixed coordinate by the CLI boundary above.

    Approval, claim, and protected terminal are always reopened from durable
    state. The independently bounded public terminal bytes must match the
    protected terminal byte-for-byte.
    """

    from itda.contracts.phase5_openrouter_recovery_v4 import parse_openrouter_terminal_v4
    from itda.domain.canonical import canonical_sha256
    from itda.pipeline.phase5_openrouter_recovery_v4 import (
        OpenRouterDurableAuthorityStateV4,
    )

    root_text = str(protected_state_root)
    state = OpenRouterDurableAuthorityStateV4.from_root_text(root_text)

    approval = state.read_approval()
    claim = state.read_claim()
    if claim.approval_sha256 != approval.approval_sha256:
        raise ValueError("OPENROUTER_V4_CLAIM_APPROVAL_BINDING_DRIFTED")
    if str(claim.protected_state_sha256) != str(state.descriptor.protected_state_sha256):
        raise ValueError("OPENROUTER_V4_CLAIM_DESCRIPTOR_BINDING_DRIFTED")
    claim_approval_bindings = {
        "request_artifact_sha256": approval.request_artifact_sha256,
        "request_file_sha256": approval.request_file_sha256,
        "predecessor_consumption_sha256": approval.predecessor_consumption_sha256,
    }
    for name, expected in claim_approval_bindings.items():
        if getattr(claim, name) != expected:
            raise ValueError(f"OPENROUTER_V4_CLAIM_{name.upper()}_DRIFTED")

    protected_terminal_bytes = state.read_protected_terminal_bytes()
    if public_terminal_bytes != protected_terminal_bytes:
        raise ValueError("OPENROUTER_V4_PUBLIC_PROTECTED_TERMINAL_DRIFTED")
    terminal_payload = json.loads(protected_terminal_bytes)
    if not isinstance(terminal_payload, dict):
        raise ValueError("OPENROUTER_V4_TERMINAL_MALFORMED")
    terminal = parse_openrouter_terminal_v4(terminal_payload)

    # Canonical byte equality between public-safe expectation and protected copy.
    from itda.domain.canonical import canonical_json_bytes

    if canonical_json_bytes(terminal.model_dump(mode="json")) != protected_terminal_bytes:
        raise ValueError("OPENROUTER_V4_PROTECTED_TERMINAL_NOT_CANONICAL")

    terminal_bindings = {
        "request_artifact_sha256": approval.request_artifact_sha256,
        "request_file_sha256": approval.request_file_sha256,
        "request_manifest_sha256": approval.request_manifest_sha256,
        "checkout_commit_sha256": approval.checkout_commit_sha256,
        "checkout_manifest_sha256": approval.checkout_manifest_sha256,
        "claim_sha256": claim.claim_sha256,
        "predecessor_consumption_sha256": approval.predecessor_consumption_sha256,
    }
    for name, expected in terminal_bindings.items():
        if getattr(terminal, name) != expected:
            raise ValueError(f"OPENROUTER_V4_TERMINAL_{name.upper()}_DRIFTED")

    # Full ledger reconstruction.
    entries = state.read_ledger_entries()
    reserves: dict[int, dict[str, object]] = {}
    commits: set[int] = set()
    recovered: set[int] = set()
    for row in entries:
        operation = row.get("operation")
        ordinal = int(row.get("attempt_number", 0))  # type: ignore[arg-type]
        if row.get("claim_sha256") != claim.claim_sha256:
            raise ValueError("OPENROUTER_V4_LEDGER_CLAIM_IDENTITY_DRIFTED")
        amount = int(row.get("amount_micro_usd", -1))
        if amount != 0 or row.get("price_status") != "EXACT_ZERO":
            raise ValueError("OPENROUTER_V4_LEDGER_PRICE_STATUS_INVALID")
        if not 1 <= ordinal <= 30:
            raise ValueError("OPENROUTER_V4_LEDGER_ORDINAL_INVALID")
        if operation == "RESERVE":
            if ordinal in reserves:
                raise ValueError("OPENROUTER_V4_DUPLICATE_RESERVE_ORDINAL")
            reserves[ordinal] = row
        elif operation == "COMMIT":
            if ordinal in commits or ordinal in recovered or ordinal not in reserves:
                raise ValueError("OPENROUTER_V4_COMMIT_ORDER_INVALID")
            if row.get("required_evidence_sha256") is None:
                raise ValueError("OPENROUTER_V4_COMMIT_EVIDENCE_REQUIRED")
            commits.add(ordinal)
        elif operation == "RECOVER_UNRESOLVED":
            if ordinal in commits or ordinal in recovered or ordinal not in reserves:
                raise ValueError("OPENROUTER_V4_RECOVERY_ORDER_INVALID")
            recovered.add(ordinal)
        elif operation == "DISPATCH":
            pass  # correlated against journal inventory below
        else:
            raise ValueError("OPENROUTER_V4_LEDGER_OPERATION_UNKNOWN")
    settled = commits | recovered
    if any(ordinal not in settled for ordinal in reserves):
        raise ValueError("OPENROUTER_V4_UNSETTLED_RESERVATION")
    if len(settled) != len(reserves):
        raise ValueError("OPENROUTER_V4_SETTLEMENT_COUNT_DRIFTED")

    counts = state.outcome_counts()
    total_attempts = sum(counts.values())
    if int(terminal.attempt_count) != total_attempts:  # type: ignore[arg-type]
        raise ValueError("OPENROUTER_V4_TERMINAL_ATTEMPT_COUNT_DRIFTED")
    committed = state.committed_exposure_micro_usd()
    if committed != 0:
        raise ValueError("OPENROUTER_V4_EXPOSURE_NOT_EXACT_ZERO")
    if canonical_sha256(entries) != str(terminal.ledger_segment_sha256):  # type: ignore[arg-type]
        raise ValueError("OPENROUTER_V4_LEDGER_DIGEST_DRIFTED")
    if state.journal_inventory_digest() != str(terminal.journal_sha256):  # type: ignore[arg-type]
        raise ValueError("OPENROUTER_V4_JOURNAL_DIGEST_DRIFTED")

    state.validate_journal_evidence_inventory()
    state.validate_raw_evidence_inventory()
    state.validate_reconciliation_inventory()

    negative_branch = terminal.status in {"DESIGNED_NEGATIVE", "FAILED_UNACTIVATED"}
    if negative_branch and state.list_profile_names():
        raise ValueError("OPENROUTER_V4_NEGATIVE_BRANCH_CARRIES_PROFILES")

    # Positive branch: full generation/profile reconstruction.
    if terminal.status == "COMPLETE_CANDIDATE_READY":
        _reconstruct_positive_evidence_v4(
            state=state,
            terminal=terminal,
            approval=approval,
            claim=claim,
        )
    state.validate_root_inventory(require_generation=terminal.status == "COMPLETE_CANDIDATE_READY")

    outcome = OpenRouterVerifiedOutcomeV4()
    outcome.terminal = terminal
    return outcome


def _reconstruct_positive_evidence_v4(
    *,
    state: object,
    terminal: object,
    approval: object,
    claim: object,
) -> None:
    """Positive-only reconstruction of generation + all 24 profiles."""

    from itda.contracts.phase5_openrouter_recovery_v4 import (
        OpenRouterGenerationV4,
        OpenRouterProfileV4,
    )

    generation_bytes = state.read_generation_bytes()  # type: ignore[attr-defined]
    generation = OpenRouterGenerationV4.model_validate_json(generation_bytes)
    if str(generation.generation_sha256) != str(terminal.generation_sha256):  # type: ignore[attr-defined]
        raise ValueError("OPENROUTER_V4_GENERATION_DIGEST_DRIFTED")
    bindings = {
        "request_artifact_sha256": approval.request_artifact_sha256,
        "request_file_sha256": approval.request_file_sha256,
        "request_manifest_sha256": approval.request_manifest_sha256,
        "checkout_commit_sha256": approval.checkout_commit_sha256,
        "checkout_manifest_sha256": approval.checkout_manifest_sha256,
        "claim_sha256": claim.claim_sha256,
        "predecessor_consumption_sha256": claim.predecessor_consumption_sha256,
        "profile_count": terminal.profile_count,  # type: ignore[attr-defined]
    }
    for name, expected in bindings.items():
        if getattr(generation, name) != expected:
            raise ValueError(f"OPENROUTER_V4_GENERATION_{name.upper()}_DRIFTED")

    from itda.pipeline.phase5_openrouter_recovery_v4 import (
        _trusted_profile_v4,
        _verified_source_bundles_v4,
        build_openrouter_plan_v4,
    )

    trusted_plan = build_openrouter_plan_v4(
        _verified_source_bundles_v4(),
        source_commit=str(approval.checkout_commit_sha256),
    )
    names = sorted(state.list_profile_names())  # type: ignore[attr-defined]
    if len(names) != 24:
        raise ValueError("OPENROUTER_V4_POSITIVE_LACKS_24_PROFILES")
    by_place: dict[str, str] = {}
    ordered: list[dict[str, object]] = []
    for name in names:
        payload = json.loads(state.read_profile_bytes(name))  # type: ignore[attr-defined]
        profile = OpenRouterProfileV4.model_validate(payload)
        place_id = str(profile.place_id)
        attempt_number = int(name.split("-", 2)[1])
        response_body = state.read_raw_response_bytes(attempt_number)  # type: ignore[attr-defined]
        trusted = _trusted_profile_v4(
            value=json.loads(response_body),
            response_body=response_body,
            place_id=place_id,
            request_sha256=str(profile.request_sha256),
            plan=trusted_plan,
        )
        if trusted != profile.model_dump(mode="json"):
            raise ValueError("OPENROUTER_V4_PROFILE_TRUSTED_LINEAGE_DRIFTED")
        if place_id in by_place:
            raise ValueError("OPENROUTER_V4_DUPLICATE_DURABLE_PROFILE")
        by_place[place_id] = str(profile.profile_sha256)
        ordered.append(payload)
    expected_profiles = {
        str(row.get("place_id")): str(row.get("profile_sha256")) for row in generation.profiles
    }
    if by_place != expected_profiles or len(expected_profiles) != 24:
        raise ValueError("OPENROUTER_V4_DURABLE_PROFILE_DIGESTS_DRIFTED")


# ---------------------------------------------------------------------------
# Real zero-argument production runner, frozen before packet generation.
# ---------------------------------------------------------------------------


def _read_secret_value_v4(path: Path) -> str:
    result, value = _inspect_v4_secret(path)
    if result != {"status": "pass"} or value is None:
        raise PermissionError("OPENROUTER_V4_SECRET_SHAPE_INVALID")
    return value


def _bind_public_entry():
    request_path_cell = OPENROUTER_V4_PUBLIC_REQUEST_PATH
    protected_root_cell = OPENROUTER_V4_PROTECTED_ROOT
    terminal_path_cell = OPENROUTER_V4_TERMINAL_OUTPUT
    secret_path_cell = REPOSITORY_ROOT / V4_SECRET_FILE_RELATIVE
    client_constructor_cell = __import__("httpx").AsyncClient

    def execute_openrouter_v4_production() -> dict[str, object]:
        import asyncio
        import hashlib

        from itda.contracts.phase5_openrouter_recovery_v4 import (
            OpenRouterProtectedStateDescriptorV4,
        )
        from itda.domain.canonical import canonical_json_bytes
        from itda.minimal_probe_bootstrap import validate_capability_process
        from itda.pipeline.phase5_openrouter_recovery_v4 import (
            OpenRouterDurableAuthorityStateV4,
            _execute_openrouter_v4_transport,
            _verified_source_bundles_v4,
            build_openloader_v4,
            build_openrouter_plan_v4,
            verify_openrouter_v4_packet_full,
        )

        validate_capability_process()
        if os.environ.get("ITDA_OFFLINE") == "1" or os.environ.get("ITDA_NO_NETWORK") == "1":
            raise PermissionError("LIVE_MODE_DISABLED")
        if os.environ.get("CI") or os.environ.get("ITDA_PROVIDER_NETWORK") != "1":
            raise PermissionError("LIVE_NETWORK_CAPABILITY_REQUIRED")
        raw = request_path_cell.read_bytes()
        verify_openrouter_v4_packet_full(raw)
        packet = build_openloader_v4(raw)
        plan = build_openrouter_plan_v4(
            _verified_source_bundles_v4(),
            source_commit=str(packet["checkout_commit_sha256"]),
        )
        if (
            packet["request_manifest_sha256"] != plan.request_manifest_sha256
            or packet["checkout_commit_sha256"] != plan.checkout_commit_sha256
        ):
            raise PermissionError("OPENROUTER_V4_PACKET_PLAN_DRIFT")
        state = OpenRouterDurableAuthorityStateV4(
            OpenRouterProtectedStateDescriptorV4.from_root(state_root=str(protected_root_cell))
        )
        claim = state.claim_once(request_artifact=packet)

        async def open_client(**kwargs: object):
            return client_constructor_cell(**kwargs)

        terminal = asyncio.run(
            _execute_openrouter_v4_transport(
                plan=plan,
                claim=claim,
                state=state,
                credential_reader=lambda: _read_secret_value_v4(secret_path_cell),
                open_client=open_client,
            )
        )
        payload = canonical_json_bytes(terminal)
        _publish_terminal_bytes_v4(terminal_path_cell, payload)
        if (
            hashlib.sha256(payload).hexdigest()
            != hashlib.sha256(state.read_protected_terminal_bytes()).hexdigest()
        ):
            raise PermissionError("OPENROUTER_V4_PUBLIC_TERMINAL_DRIFT")
        return terminal

    return execute_openrouter_v4_production


execute_openrouter_v4_production = _bind_public_entry()


# ---------------------------------------------------------------------------
# Public main.
# ---------------------------------------------------------------------------


def _preflight_payload(*, verify_only: bool) -> dict[str, object]:
    """Provider-free packet/snapshot/source authority summary.

    A PRESENT packet is verified FULLY — canonical bytes, exact digests,
    24 ordered first passes, capability facts false, predecessor dual-fact
    binding, and source-parent consistency — never merely ``exists()``.
    An absent packet with ``--verify-only`` is the named failure
    ``OPENROUTER_V4_PACKET_ABSENT``.
    """

    from itda.contracts.phase5_openrouter_recovery_v4 import (
        OPENROUTER_V4_SNAPSHOT_SHA256,
        load_openrouter_snapshot_v4,
    )
    from itda.pipeline.phase5_openrouter_recovery_v4 import (
        require_fixed_openrouter_v4_paths,
    )

    require_fixed_openrouter_v4_paths()
    snapshot = load_openrouter_snapshot_v4()
    packet_present = False
    packet_verified: dict[str, object] | None = None
    if OPENROUTER_V4_PUBLIC_REQUEST_PATH.is_file() and not (
        OPENROUTER_V4_PUBLIC_REQUEST_PATH.is_symlink()
    ):
        from itda.cli.materialize_phase5_demo_profiles import _read_bounded_regular

        raw = _read_bounded_regular(
            OPENROUTER_V4_PUBLIC_REQUEST_PATH, maximum_bytes=8 * 1024 * 1024
        )
        from itda.pipeline.phase5_openrouter_recovery_v4 import (
            verify_openrouter_v4_packet_full,
        )

        packet_verified = verify_openrouter_v4_packet_full(raw)
        packet_present = True
    elif verify_only:
        raise FileNotFoundError("OPENROUTER_V4_PACKET_ABSENT")
    payload: dict[str, object] = {
        "schema_version": "itda.phase5-openrouter-recovery-v4-preflight.v2",
        "authority_id": snapshot.authority_id,
        "endpoint": snapshot.endpoint["url"],
        "model": snapshot.model["slug"],
        "snapshot_sha256": str(snapshot.snapshot_sha256),
        "expected_snapshot_sha256": OPENROUTER_V4_SNAPSHOT_SHA256,
        "packet_present": packet_present,
        "network_attempted": False,
        "client_constructed": False,
        "secret_read": False,
    }
    if packet_verified is not None:
        payload["packet_request_artifact_sha256"] = packet_verified["request_artifact_sha256"]
        payload["packet_checkout_commit_sha256"] = packet_verified["checkout_commit_sha256"]
        payload["packet_fully_verified"] = True
    return payload


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0] not in V4_PUBLIC_COMMANDS:
        if arguments and arguments[0] in V4_CAPABILITY_COMMANDS:
            print(_USE_BOOTSTRAP_MESSAGE, file=sys.stderr)
        else:
            print("OPENROUTER_V4_COMMAND_REQUIRED", file=sys.stderr)
        return 2
    args = build_public_parser().parse_args(arguments)
    try:
        if args.command == "openrouter-recovery-v4-preflight":
            if args.require_committed_clean_source:
                from itda.cli.materialize_phase5_demo_profiles import (
                    _require_minimal_probe_committed_clean_source as clean_source,
                )

                clean_source()
            request_path = _resolve_fixed(
                args.request, OPENROUTER_V4_PUBLIC_REQUEST_PATH, "v4 request"
            )
            del request_path
            payload = _preflight_payload(verify_only=args.verify_only)
            _print_payload(payload, json_output=args.json)
            return 0
        if args.command == "openrouter-recovery-v4-secret-shape":
            secret_file = _fixed_secret_path(args.secret_env_file)
            result = validate_v4_secret_shape(secret_file)
            if result["status"] != "pass":
                print(result["error"], file=sys.stderr)
                return 2
            if not args.quiet:
                _print_payload(result, json_output=args.json)
            return 0
        if args.command == "openrouter-recovery-v4-verify":
            from itda.cli.materialize_phase5_demo_profiles import (
                _read_bounded_regular,
            )

            terminal_path = _fixed_terminal_path(args.terminal)
            from itda.pipeline.phase5_openrouter_recovery_v4 import (
                require_fixed_openrouter_v4_paths,
            )

            require_fixed_openrouter_v4_paths(terminal_output=terminal_path)
            public_terminal_bytes = _read_bounded_regular(
                terminal_path, maximum_bytes=2 * 1024 * 1024
            )
            outcome = verify_openrouter_v4_outcome(
                protected_state_root=OPENROUTER_V4_PROTECTED_ROOT,
                public_terminal_bytes=public_terminal_bytes,
            )
            terminal = outcome.terminal
            positive_assertion = False
            if args.require_positive:
                assert_openrouter_v4_positive(
                    protected_state_root=OPENROUTER_V4_PROTECTED_ROOT,
                    public_terminal_bytes=public_terminal_bytes,
                )
                positive_assertion = True
            _print_payload(
                {
                    "status": terminal.status,
                    "reason": terminal.reason,
                    "terminal_sha256": str(terminal.terminal_sha256),
                    "neutral_verified": True,
                    "protected_verified": True,
                    "positive_assertion": positive_assertion,
                    "network_attempted": bool(terminal.network_attempted),
                    "lifecycle_mutated": False,
                },
                json_output=args.json,
            )
            return 0
        # classify
        from itda.cli.materialize_phase5_demo_profiles import _read_bounded_regular

        terminal_path = _fixed_terminal_path(args.terminal)
        public_terminal_bytes = _read_bounded_regular(terminal_path, maximum_bytes=2 * 1024 * 1024)
        disposition = classify_openrouter_v4_outcome(
            protected_state_root=OPENROUTER_V4_PROTECTED_ROOT,
            public_terminal_bytes=public_terminal_bytes,
        )
        if args.value_only:
            print(disposition)
        else:
            _print_payload({"disposition": disposition}, json_output=args.json)
        return 0
    except (
        FileNotFoundError,
        OSError,
        PermissionError,
        RuntimeError,
        ValueError,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ) as error:
        message = str(error)
        if message.startswith(("OPENROUTER_V4_", "LIVE_", "LIVE_MODE")):
            print(message, file=sys.stderr)
        else:
            print("OPENROUTER_V4_REJECTED", file=sys.stderr)
        return 2


def _capability_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    commands = parser.add_subparsers(dest="command", required=True)
    install = commands.add_parser("openrouter-recovery-v4-install-approval")
    install.add_argument("--request", type=Path, required=True)
    install.add_argument("--protected-state-root", type=Path, required=True)
    install.add_argument("--secret-env-file", type=Path, required=True)
    install.add_argument("--approval-payload-sha256", required=True)
    install.add_argument("--json", action="store_true")
    live = commands.add_parser("openrouter-recovery-v4-live")
    live.add_argument("--request", type=Path, required=True)
    live.add_argument("--protected-state-root", type=Path, required=True)
    live.add_argument("--secret-env-file", type=Path, required=True)
    live.add_argument("--terminal-output", type=Path, required=True)
    live.add_argument("--json", action="store_true")
    reconcile = commands.add_parser("openrouter-recovery-v4-reconcile")
    reconcile.add_argument("--request", type=Path, required=True)
    reconcile.add_argument("--protected-state-root", type=Path, required=True)
    reconcile.add_argument("--terminal-output", type=Path, required=True)
    reconcile.add_argument("--json", action="store_true")
    return parser


def _load_fixed_packet_v4() -> tuple[dict[str, object], bytes]:
    from itda.contracts.phase5_openrouter_recovery_v4 import read_stable_bounded_raw
    from itda.pipeline.phase5_openrouter_recovery_v4 import verify_openrouter_v4_packet_full

    raw = read_stable_bounded_raw(OPENROUTER_V4_PUBLIC_REQUEST_PATH, maximum=8 * 1024 * 1024)
    return verify_openrouter_v4_packet_full(raw), raw


def _publish_terminal_bytes_v4(path: Path, serialized: bytes) -> None:
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    parent_fd = os.open(path.anchor, directory_flags)
    try:
        for component in path.parts[1:-1]:
            try:
                metadata = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                os.mkdir(component, 0o700, dir_fd=parent_fd)
                metadata = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise PermissionError("OPENROUTER_V4_PUBLIC_TERMINAL_PARENT_INVALID")
            child_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = child_fd
        parent_metadata = os.fstat(parent_fd)
        if parent_metadata.st_uid != os.getuid() or stat.S_IMODE(parent_metadata.st_mode) & 0o022:
            raise PermissionError("OPENROUTER_V4_PUBLIC_TERMINAL_PARENT_UNSAFE")
        staging_name = f".{path.name}.stage-{__import__('uuid').uuid4().hex}"
        descriptor: int | None = None
        try:
            descriptor = os.open(
                staging_name,
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=parent_fd,
            )
            os.fchmod(descriptor, 0o600)
            written = 0
            while written < len(serialized):
                count = os.write(descriptor, serialized[written:])
                if count <= 0:
                    raise OSError("OPENROUTER_V4_PUBLIC_TERMINAL_SHORT_WRITE")
                written += count
            os.fsync(descriptor)
            staging_metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(staging_metadata.st_mode)
                or staging_metadata.st_uid != os.getuid()
                or stat.S_IMODE(staging_metadata.st_mode) != 0o600
                or staging_metadata.st_nlink != 1
                or staging_metadata.st_size != len(serialized)
            ):
                raise PermissionError("OPENROUTER_V4_PUBLIC_TERMINAL_STAGING_INVALID")
            _rename_noreplace_at(parent_fd, staging_name, parent_fd, path.name)
            try:
                published_metadata = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
                pinned_metadata = os.fstat(descriptor)
                published_valid = (
                    stat.S_ISREG(published_metadata.st_mode)
                    and published_metadata.st_uid == os.getuid()
                    and stat.S_IMODE(published_metadata.st_mode) == 0o600
                    and published_metadata.st_nlink == 1
                    and published_metadata.st_size == len(serialized)
                    and (published_metadata.st_dev, published_metadata.st_ino)
                    == (pinned_metadata.st_dev, pinned_metadata.st_ino)
                    and pinned_metadata.st_nlink == 1
                    and pinned_metadata.st_size == len(serialized)
                    and os.pread(descriptor, len(serialized) + 1, 0) == serialized
                )
                if not published_valid:
                    current = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) == (
                        pinned_metadata.st_dev,
                        pinned_metadata.st_ino,
                    ):
                        os.unlink(path.name, dir_fd=parent_fd)
                        os.fsync(parent_fd)
                    raise PermissionError("OPENROUTER_V4_PUBLIC_TERMINAL_PUBLISHED_INVALID")
                os.fsync(parent_fd)
            finally:
                os.close(descriptor)
                descriptor = None
        finally:
            if descriptor is not None:
                os.close(descriptor)
            with suppress(FileNotFoundError):
                os.unlink(staging_name, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)


def _publish_public_terminal_v4(payload: dict[str, object]) -> None:
    from itda.domain.canonical import canonical_json_bytes

    _publish_terminal_bytes_v4(OPENROUTER_V4_TERMINAL_OUTPUT, canonical_json_bytes(payload))


def v4_capability_dispatch(argv: list[str]) -> int:
    from itda.contracts.phase5_openrouter_recovery_v4 import (
        OPENROUTER_V4_APPROVAL_SCHEMA,
        OpenRouterApprovalBindingV4,
        OpenRouterProtectedStateDescriptorV4,
        build_openrouter_terminal_v4,
    )
    from itda.domain.canonical import canonical_sha256
    from itda.minimal_probe_bootstrap import validate_capability_process
    from itda.pipeline.phase5_openrouter_recovery_v4 import (
        OpenRouterDurableAuthorityStateV4,
    )

    args = _capability_parser().parse_args(argv)
    try:
        validate_capability_process()
        _resolve_fixed(args.request, OPENROUTER_V4_PUBLIC_REQUEST_PATH, "v4 request")
        _resolve_fixed(args.protected_state_root, OPENROUTER_V4_PROTECTED_ROOT, "v4 protected root")
        if hasattr(args, "terminal_output"):
            _fixed_terminal_path(args.terminal_output)
        packet, raw = _load_fixed_packet_v4()
        descriptor = OpenRouterProtectedStateDescriptorV4.from_root(
            state_root=str(OPENROUTER_V4_PROTECTED_ROOT)
        )
        state = OpenRouterDurableAuthorityStateV4(descriptor)
        if args.command == "openrouter-recovery-v4-install-approval":
            secret_path = _fixed_secret_path(args.secret_env_file)
            if validate_v4_secret_metadata(secret_path) != {"status": "pass"}:
                raise PermissionError("OPENROUTER_V4_SECRET_METADATA_INVALID")
            if packet["request_artifact_sha256"] != args.approval_payload_sha256:
                raise PermissionError("OPENROUTER_V4_APPROVAL_MISMATCH")
            predecessor = packet["predecessor_consumption"]
            approval_fields = {
                "schema_version": OPENROUTER_V4_APPROVAL_SCHEMA,
                "authority_id": packet["authority_id"],
                "decision": "APPROVED",
                "request_artifact_sha256": packet["request_artifact_sha256"],
                "request_file_sha256": __import__("hashlib").sha256(raw).hexdigest(),
                "request_manifest_sha256": packet["request_manifest_sha256"],
                "membership_sha256": packet["membership_sha256"],
                "checkout_manifest_sha256": packet["checkout_manifest_sha256"],
                "checkout_commit_sha256": packet["checkout_commit_sha256"],
                "protected_state_sha256": descriptor.protected_state_sha256,
                "predecessor_consumption_sha256": predecessor["consumption_sha256"],
                "provider_lane": packet["provider_lane"],
                "endpoint": packet["endpoint"],
                "model": packet["model"],
                "snapshot_sha256": packet["snapshot_sha256"],
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
            approval = OpenRouterApprovalBindingV4.model_validate(
                {**approval_fields, "approval_sha256": canonical_sha256(approval_fields)}
            )
            status = state.install_approval(approval, request_artifact=packet)
            _print_payload(status, json_output=args.json)
            return 0
        if args.command == "openrouter-recovery-v4-live":
            _fixed_secret_path(args.secret_env_file)
            terminal = execute_openrouter_v4_production()
            _print_payload(
                {"status": terminal["status"], "reason": terminal["reason"]},
                json_output=args.json,
            )
            return 0
        claim = state.read_claim()
        approval = state.read_approval()
        recovered = state.reconcile_interrupted(claim=claim)
        if recovered is None:
            raise PermissionError("OPENROUTER_V4_RECONCILIATION_NOT_REQUIRED")
        counts = state.outcome_counts()
        state.ensure_profiles_dir()
        state.ensure_raw_evidence_dir()
        terminal = build_openrouter_terminal_v4(
            status="FAILED_UNACTIVATED",
            reason=str(recovered["reason"]),
            request_artifact_sha256=str(approval.request_artifact_sha256),
            request_file_sha256=str(approval.request_file_sha256),
            request_manifest_sha256=str(approval.request_manifest_sha256),
            checkout_commit_sha256=str(approval.checkout_commit_sha256),
            checkout_manifest_sha256=str(approval.checkout_manifest_sha256),
            claim_sha256=str(claim.claim_sha256),
            predecessor_consumption_sha256=str(claim.predecessor_consumption_sha256),
            generation=None,
            ledger_segment_sha256=state.ledger_segment_sha256(),
            journal_sha256=state.journal_inventory_digest(),
            attempt_count=sum(counts.values()),
            reserve_count=sum(row["operation"] == "RESERVE" for row in state.read_ledger_entries()),
            http_response_count=counts["HTTP_RESPONSE"],
            transport_error_count=counts["TRANSPORT_ERROR"],
            credential_stripped_count=counts["CREDENTIAL_RESPONSE_STRIPPED"],
            local_pre_send_failure_count=counts["LOCAL_PRE_SEND_FAILURE"],
            secret_read=False,
            client_constructed=bool(recovered["client_constructed"]),
            network_attempted=False,
        ).model_dump(mode="json")
        state.publish_terminal(terminal=terminal)
        _publish_public_terminal_v4(terminal)
        _print_payload(
            {"status": terminal["status"], "reason": terminal["reason"]},
            json_output=args.json,
        )
        return 0
    except (OSError, PermissionError, RuntimeError, ValueError) as error:
        message = str(error)
        print(
            message
            if message.startswith(("OPENROUTER_V4_", "LIVE_", "LIVE_MODE"))
            else "OPENROUTER_V4_REJECTED",
            file=sys.stderr,
        )
        return 2


__all__ = [
    "OpenRouterVerifiedOutcomeV4",
    "V4_CAPABILITY_COMMANDS",
    "V4_PUBLIC_COMMANDS",
    "assert_openrouter_v4_positive",
    "build_public_parser",
    "classify_openrouter_v4_outcome",
    "execute_openrouter_v4_production",
    "main",
    "validate_v4_secret_shape",
    "verify_openrouter_v4_outcome",
]
