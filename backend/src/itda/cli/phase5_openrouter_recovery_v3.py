"""Provider-free OpenRouter r3/v3 CLI: public commands and sealed dispatch.

Public surface (provider-free, reachable through
``python -m itda.cli.materialize_phase5_demo_profiles`` delegation or direct
module invocation):

- ``openrouter-recovery-v3-preflight``   — packet/snapshot/source preflight.
- ``openrouter-recovery-v3-secret-shape`` — fixed-path secret SHAPE check;
  pass/named-error only; never a value/length/prefix/digest/identity.
- ``openrouter-recovery-v3-verify``      — neutral verification reopening
  every persisted evidence class independently (``--require-positive`` is
  the separate strict-positive step).
- ``openrouter-recovery-v3-classify``    — disposition over verified outcomes.

Capability surface (install/live/reconcile) is bootstrap-only: the public
main rejects those names fail-closed; only the sanitized stdlib bootstrap
entrypoint may route them through :func:`v3_capability_dispatch`.

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
from pathlib import Path

from itda.contracts.phase5_openrouter_recovery_v3_paths import (
    OPENROUTER_V3_PROTECTED_ROOT,
    OPENROUTER_V3_PUBLIC_REQUEST_PATH,
    OPENROUTER_V3_TERMINAL_OUTPUT,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]

V3_SECRET_FILE_RELATIVE = ".secrets/itda-openrouter.env"
V3_SECRET_ENV_KEY = "OPENROUTER_API_KEY"
V3_PUBLIC_COMMANDS = (
    "openrouter-recovery-v3-preflight",
    "openrouter-recovery-v3-secret-shape",
    "openrouter-recovery-v3-verify",
    "openrouter-recovery-v3-classify",
)
V3_CAPABILITY_COMMANDS = (
    "openrouter-recovery-v3-install-approval",
    "openrouter-recovery-v3-live",
    "openrouter-recovery-v3-reconcile",
)

_USE_BOOTSTRAP_MESSAGE = "USE_OPENROUTER_V3_BOOTSTRAP_ENTRYPOINT"

# Test-only isolated-root markers shared with the pipeline mock seam.
_V3_TEST_ROOT_MARKERS = ("/tmp/", "/private/tmp/", "/var/folders/")


def build_public_parser() -> argparse.ArgumentParser:
    """The provider-free public parser; capability names are absent."""

    parser = argparse.ArgumentParser(
        prog="itda.cli.phase5_openrouter_recovery_v3",
        description="provider-free openrouter r3/v3 recovery commands",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name in V3_PUBLIC_COMMANDS:
        sub = commands.add_parser(name)
        if name == "openrouter-recovery-v3-preflight":
            sub.add_argument("--request", type=Path, required=True)
            sub.add_argument("--require-committed-clean-source", action="store_true")
            sub.add_argument("--verify-only", action="store_true")
            sub.add_argument("--json", action="store_true")
        elif name == "openrouter-recovery-v3-secret-shape":
            sub.add_argument("--secret-env-file", type=Path, required=True)
            sub.add_argument("--quiet", action="store_true")
        elif name == "openrouter-recovery-v3-verify":
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
    if normalized != expected or any(
        part in {"", ".", ".."} for part in normalized.parts[1:]
    ):
        raise PermissionError(f"caller-selected {label} is forbidden")
    return normalized


def _fixed_terminal_path(path: Path) -> Path:
    return _resolve_fixed(path, OPENROUTER_V3_TERMINAL_OUTPUT, "v3 terminal")


def _fixed_secret_path(path: Path) -> Path:
    expected = REPOSITORY_ROOT / V3_SECRET_FILE_RELATIVE
    resolved = (path if path.is_absolute() else REPOSITORY_ROOT / path).resolve(
        strict=False
    )
    if (
        resolved != expected
        or any(part in {"", ".", ".."} for part in resolved.parts[1:])
        or resolved.parent.name != ".secrets"
    ):
        raise PermissionError("caller-selected v3 secret file is forbidden")
    return resolved


# ---------------------------------------------------------------------------
# Secret shape validation — pass / named error only, never value-derived.
# ---------------------------------------------------------------------------


def validate_v3_secret_shape(path: Path) -> dict[str, object]:
    """Validate ONLY the fixed shape contract of one env-file candidate.

    Contract: parent directory 0700 owned by the current user; the file is a
    regular non-symlink single-link 0600 file owned by the current user with
    exactly one UTF-8 record ``OPENROUTER_API_KEY=<nonempty>``.  Returns
    ``{"status": "pass"}`` or ``{"status": "fail", "error": <named code>}``.
    No value, length, prefix, digest, identity digest, inode, device, or any
    other value-derived metadata ever appears in the result.

    The validator operates strictly on the caller-supplied synthetic path
    (tests use temp roots); it performs no network I/O and constructs no
    client.  Production use passes the FIXED repository coordinate only.
    """

    def fail(code: str) -> dict[str, object]:
        return {"status": "fail", "error": code}

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
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
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
            raw = os.read(descriptor, before.st_size + 1)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_fd)
    if len(raw) != before.st_size or (
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
    try:
        text = raw.decode("utf-8").removesuffix("\n")
    except UnicodeDecodeError:
        return fail("ENCODING_INVALID")
    if "\n" in text or "\r" in text or "=" not in text:
        return fail("RECORD_INVALID")
    key, value = text.split("=", 1)
    if key != V3_SECRET_ENV_KEY or not value.strip():
        return fail("RECORD_INVALID")
    return {"status": "pass"}


# ---------------------------------------------------------------------------
# Neutral verified outcome + classifier + strict positive assertion.
# ---------------------------------------------------------------------------


class OpenRouterVerifiedOutcomeV3:
    __slots__ = ("terminal",)

    terminal: object


def classify_openrouter_v3_outcome(
    *, protected_state_root: Path, public_terminal_bytes: bytes
) -> str:
    outcome = verify_openrouter_v3_outcome(
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
    raise ValueError("OPENROUTER_V3_DISPOSITION_UNKNOWN")


def assert_openrouter_v3_positive(
    *, protected_state_root: Path, public_terminal_bytes: bytes
) -> None:
    outcome = verify_openrouter_v3_outcome(
        protected_state_root=protected_state_root,
        public_terminal_bytes=public_terminal_bytes,
    )
    if getattr(outcome.terminal, "status", None) != "COMPLETE_CANDIDATE_READY":
        raise ValueError("OPENROUTER_V3_NOT_STRICT_POSITIVE")


# ---------------------------------------------------------------------------
# Neutral verification: independent reopen/reconstruct of persisted evidence.
# ---------------------------------------------------------------------------


def verify_openrouter_v3_outcome(
    *, protected_state_root: Path, public_terminal_bytes: bytes
) -> OpenRouterVerifiedOutcomeV3:
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

    from itda.contracts.phase5_openrouter_recovery_v3 import parse_openrouter_terminal_v3
    from itda.domain.canonical import canonical_sha256
    from itda.pipeline.phase5_openrouter_recovery_v3 import (
        OpenRouterDurableAuthorityStateV3,
    )

    root_text = str(protected_state_root)
    state = OpenRouterDurableAuthorityStateV3.from_root_text(root_text)

    approval = state.read_approval()
    claim = state.read_claim()
    if claim.approval_sha256 != approval.approval_sha256:
        raise ValueError("OPENROUTER_V3_CLAIM_APPROVAL_BINDING_DRIFTED")
    if str(claim.protected_state_sha256) != str(
        state.descriptor.protected_state_sha256
    ):
        raise ValueError("OPENROUTER_V3_CLAIM_DESCRIPTOR_BINDING_DRIFTED")
    claim_approval_bindings = {
        "request_artifact_sha256": approval.request_artifact_sha256,
        "request_file_sha256": approval.request_file_sha256,
        "predecessor_consumption_sha256": approval.predecessor_consumption_sha256,
    }
    for name, expected in claim_approval_bindings.items():
        if getattr(claim, name) != expected:
            raise ValueError(f"OPENROUTER_V3_CLAIM_{name.upper()}_DRIFTED")

    protected_terminal_bytes = state.read_protected_terminal_bytes()
    if public_terminal_bytes != protected_terminal_bytes:
        raise ValueError("OPENROUTER_V3_PUBLIC_PROTECTED_TERMINAL_DRIFTED")
    terminal_payload = json.loads(protected_terminal_bytes)
    if not isinstance(terminal_payload, dict):
        raise ValueError("OPENROUTER_V3_TERMINAL_MALFORMED")
    terminal = parse_openrouter_terminal_v3(terminal_payload)

    # Canonical byte equality between public-safe expectation and protected copy.
    from itda.domain.canonical import canonical_json_bytes

    if canonical_json_bytes(terminal.model_dump(mode="json")) != protected_terminal_bytes:
        raise ValueError("OPENROUTER_V3_PROTECTED_TERMINAL_NOT_CANONICAL")

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
            raise ValueError(f"OPENROUTER_V3_TERMINAL_{name.upper()}_DRIFTED")

    # Full ledger reconstruction.
    entries = state.read_ledger_entries()
    reserves: dict[int, dict[str, object]] = {}
    commits: set[int] = set()
    recovered: set[int] = set()
    for row in entries:
        operation = row.get("operation")
        ordinal = int(row.get("attempt_number", 0))  # type: ignore[arg-type]
        if row.get("claim_sha256") != claim.claim_sha256:
            raise ValueError("OPENROUTER_V3_LEDGER_CLAIM_IDENTITY_DRIFTED")
        amount = int(row.get("amount_micro_usd", -1))
        if amount != 0 or row.get("price_status") != "EXACT_ZERO":
            raise ValueError("OPENROUTER_V3_LEDGER_PRICE_STATUS_INVALID")
        if not 1 <= ordinal <= 30:
            raise ValueError("OPENROUTER_V3_LEDGER_ORDINAL_INVALID")
        if operation == "RESERVE":
            if ordinal in reserves:
                raise ValueError("OPENROUTER_V3_DUPLICATE_RESERVE_ORDINAL")
            reserves[ordinal] = row
        elif operation == "COMMIT":
            if ordinal in commits or ordinal in recovered or ordinal not in reserves:
                raise ValueError("OPENROUTER_V3_COMMIT_ORDER_INVALID")
            if row.get("required_evidence_sha256") is None:
                raise ValueError("OPENROUTER_V3_COMMIT_EVIDENCE_REQUIRED")
            commits.add(ordinal)
        elif operation == "RECOVER_UNRESOLVED":
            if ordinal in commits or ordinal in recovered or ordinal not in reserves:
                raise ValueError("OPENROUTER_V3_RECOVERY_ORDER_INVALID")
            recovered.add(ordinal)
        elif operation == "DISPATCH":
            pass  # correlated against journal inventory below
        else:
            raise ValueError("OPENROUTER_V3_LEDGER_OPERATION_UNKNOWN")
    settled = commits | recovered
    if any(ordinal not in settled for ordinal in reserves):
        raise ValueError("OPENROUTER_V3_UNSETTLED_RESERVATION")
    if len(settled) != len(reserves):
        raise ValueError("OPENROUTER_V3_SETTLEMENT_COUNT_DRIFTED")

    counts = state.outcome_counts()
    total_attempts = sum(counts.values())
    if int(terminal.attempt_count) != total_attempts:  # type: ignore[arg-type]
        raise ValueError("OPENROUTER_V3_TERMINAL_ATTEMPT_COUNT_DRIFTED")
    committed = state.committed_exposure_micro_usd()
    if committed != 0:
        raise ValueError("OPENROUTER_V3_EXPOSURE_NOT_EXACT_ZERO")
    if canonical_sha256(entries) != str(terminal.ledger_segment_sha256):  # type: ignore[arg-type]
        raise ValueError("OPENROUTER_V3_LEDGER_DIGEST_DRIFTED")
    if state.journal_inventory_digest() != str(terminal.journal_sha256):  # type: ignore[arg-type]
        raise ValueError("OPENROUTER_V3_JOURNAL_DIGEST_DRIFTED")

    state.validate_journal_evidence_inventory()
    state.validate_raw_evidence_inventory()
    state.validate_reconciliation_inventory()

    negative_branch = terminal.status in {"DESIGNED_NEGATIVE", "FAILED_UNACTIVATED"}
    if negative_branch and state.list_profile_names():
        raise ValueError("OPENROUTER_V3_NEGATIVE_BRANCH_CARRIES_PROFILES")

    # Positive branch: full generation/profile reconstruction.
    if terminal.status == "COMPLETE_CANDIDATE_READY":
        _reconstruct_positive_evidence_v3(
            state=state,
            terminal=terminal,
            approval=approval,
            claim=claim,
        )
    state.validate_root_inventory(require_generation=terminal.status == "COMPLETE_CANDIDATE_READY")

    outcome = OpenRouterVerifiedOutcomeV3()
    outcome.terminal = terminal
    return outcome


def _reconstruct_positive_evidence_v3(
    *,
    state: object,
    terminal: object,
    approval: object,
    claim: object,
) -> None:
    """Positive-only reconstruction of generation + all 24 profiles."""

    from itda.contracts.phase5_openrouter_recovery_v3 import (
        OpenRouterGenerationV3,
        OpenRouterProfileV3,
    )

    generation_bytes = state.read_generation_bytes()  # type: ignore[attr-defined]
    generation = OpenRouterGenerationV3.model_validate_json(generation_bytes)
    if str(generation.generation_sha256) != str(terminal.generation_sha256):  # type: ignore[attr-defined]
        raise ValueError("OPENROUTER_V3_GENERATION_DIGEST_DRIFTED")
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
            raise ValueError(f"OPENROUTER_V3_GENERATION_{name.upper()}_DRIFTED")

    names = sorted(state.list_profile_names())  # type: ignore[attr-defined]
    if len(names) != 24:
        raise ValueError("OPENROUTER_V3_POSITIVE_LACKS_24_PROFILES")
    by_place: dict[str, str] = {}
    ordered: list[dict[str, object]] = []
    for name in names:
        payload = json.loads(state.read_profile_bytes(name))  # type: ignore[attr-defined]
        profile = OpenRouterProfileV3.model_validate(payload)
        place_id = str(profile.place_id)
        if place_id in by_place:
            raise ValueError("OPENROUTER_V3_DUPLICATE_DURABLE_PROFILE")
        by_place[place_id] = str(profile.profile_sha256)
        ordered.append(payload)
    expected_profiles = {
        str(row.get("place_id")): str(row.get("profile_sha256"))
        for row in generation.profiles
    }
    if by_place != expected_profiles or len(expected_profiles) != 24:
        raise ValueError("OPENROUTER_V3_DURABLE_PROFILE_DIGESTS_DRIFTED")


# ---------------------------------------------------------------------------
# Sealed zero-argument production runner.
#
# Plan 05-38 exposes the ENTRY NAME only.  The runner is a zero-argument,
# import-time-sealed boundary: it runs the sanitized-entrypoint process gate
# and the offline/network fail-closed gates FIRST — in every environment this
# plan can run in (tests/CI/offline) it rejects before any packet read,
# client construction, credential access, or protected-root work.  The actual
# live execution body is activated by Plan 05-39's separate human gate; until
# then no caller-injectable root/path/runner/client/credential parameter
# exists on this surface at all.
# ---------------------------------------------------------------------------


def _bind_public_entry():
    """Build THE zero-arg production entry over frozen import-time cells.

    The cells pin the exact production coordinates at IMPORT time so a
    post-import monkeypatch of the module constants cannot redirect the
    entry.  Plan 05-38 keeps the body sealed behind the fail-closed gates;
    Plan 05-39 activates the one-shot live execution.
    """

    request_path_cell = OPENROUTER_V3_PUBLIC_REQUEST_PATH
    protected_root_cell = OPENROUTER_V3_PROTECTED_ROOT
    terminal_path_cell = OPENROUTER_V3_TERMINAL_OUTPUT

    def execute_openrouter_v3_production() -> dict[str, object]:
        # Touching the cells keeps them captured in THIS closure (no module
        # global lookup at call time) without observing anything.
        assert (request_path_cell, protected_root_cell, terminal_path_cell) is not None
        from itda.minimal_probe_bootstrap import validate_capability_process

        validate_capability_process()
        if (
            os.environ.get("ITDA_OFFLINE") == "1"
            or os.environ.get("ITDA_NO_NETWORK") == "1"
        ):
            raise PermissionError("LIVE_MODE_DISABLED")
        if os.environ.get("CI") or os.environ.get("ITDA_PROVIDER_NETWORK") != "1":
            raise PermissionError("LIVE_NETWORK_CAPABILITY_REQUIRED")
        # Sealed until Plan 05-39 activates the one-shot live body behind a
        # fresh exact human approval; nothing below this point exists yet.
        raise PermissionError(_USE_BOOTSTRAP_MESSAGE)

    return execute_openrouter_v3_production


execute_openrouter_v3_production = _bind_public_entry()


# ---------------------------------------------------------------------------
# Public main.
# ---------------------------------------------------------------------------


def _preflight_payload(*, verify_only: bool) -> dict[str, object]:
    """Provider-free packet/snapshot/source authority summary.

    A PRESENT packet is verified FULLY — canonical bytes, exact digests,
    24 ordered first passes, capability facts false, predecessor dual-fact
    binding, and source-parent consistency — never merely ``exists()``.
    An absent packet with ``--verify-only`` is the named failure
    ``OPENROUTER_V3_PACKET_ABSENT``.
    """

    from itda.contracts.phase5_openrouter_recovery_v3 import (
        OPENROUTER_V3_SNAPSHOT_SHA256,
        load_openrouter_snapshot_v3,
    )
    from itda.pipeline.phase5_openrouter_recovery_v3 import (
        require_fixed_openrouter_v3_paths,
    )

    require_fixed_openrouter_v3_paths()
    snapshot = load_openrouter_snapshot_v3()
    packet_present = False
    packet_verified: dict[str, object] | None = None
    if OPENROUTER_V3_PUBLIC_REQUEST_PATH.is_file() and not (
        OPENROUTER_V3_PUBLIC_REQUEST_PATH.is_symlink()
    ):
        from itda.cli.materialize_phase5_demo_profiles import _read_bounded_regular

        raw = _read_bounded_regular(
            OPENROUTER_V3_PUBLIC_REQUEST_PATH, maximum_bytes=8 * 1024 * 1024
        )
        from itda.pipeline.phase5_openrouter_recovery_v3 import (
            verify_openrouter_v3_packet_full,
        )

        packet_verified = verify_openrouter_v3_packet_full(raw)
        packet_present = True
    elif verify_only:
        raise FileNotFoundError("OPENROUTER_V3_PACKET_ABSENT")
    payload: dict[str, object] = {
        "schema_version": "itda.phase5-openrouter-recovery-v3-preflight.v2",
        "authority_id": snapshot.authority_id,
        "endpoint": snapshot.endpoint["url"],
        "model": snapshot.model["slug"],
        "snapshot_sha256": str(snapshot.snapshot_sha256),
        "expected_snapshot_sha256": OPENROUTER_V3_SNAPSHOT_SHA256,
        "packet_present": packet_present,
        "network_attempted": False,
        "client_constructed": False,
        "secret_read": False,
    }
    if packet_verified is not None:
        payload["packet_request_artifact_sha256"] = packet_verified[
            "request_artifact_sha256"
        ]
        payload["packet_checkout_commit_sha256"] = packet_verified[
            "checkout_commit_sha256"
        ]
        payload["packet_fully_verified"] = True
    return payload


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0] not in V3_PUBLIC_COMMANDS:
        if arguments and arguments[0] in V3_CAPABILITY_COMMANDS:
            print(_USE_BOOTSTRAP_MESSAGE, file=sys.stderr)
        else:
            print("OPENROUTER_V3_COMMAND_REQUIRED", file=sys.stderr)
        return 2
    args = build_public_parser().parse_args(arguments)
    try:
        if args.command == "openrouter-recovery-v3-preflight":
            if args.require_committed_clean_source:
                from itda.cli.materialize_phase5_demo_profiles import (
                    _require_minimal_probe_committed_clean_source as clean_source,
                )

                clean_source()
            request_path = _resolve_fixed(
                args.request, OPENROUTER_V3_PUBLIC_REQUEST_PATH, "v3 request"
            )
            del request_path
            payload = _preflight_payload(verify_only=args.verify_only)
            _print_payload(payload, json_output=args.json)
            return 0
        if args.command == "openrouter-recovery-v3-secret-shape":
            secret_file = _fixed_secret_path(args.secret_env_file)
            result = validate_v3_secret_shape(secret_file)
            if result["status"] != "pass":
                print(result["error"], file=sys.stderr)
                return 2
            if not args.quiet:
                _print_payload(result, json_output=args.json)
            return 0
        if args.command == "openrouter-recovery-v3-verify":
            from itda.cli.materialize_phase5_demo_profiles import (
                _read_bounded_regular,
            )

            terminal_path = _fixed_terminal_path(args.terminal)
            from itda.pipeline.phase5_openrouter_recovery_v3 import (
                require_fixed_openrouter_v3_paths,
            )

            require_fixed_openrouter_v3_paths(terminal_output=terminal_path)
            public_terminal_bytes = _read_bounded_regular(
                terminal_path, maximum_bytes=2 * 1024 * 1024
            )
            outcome = verify_openrouter_v3_outcome(
                protected_state_root=OPENROUTER_V3_PROTECTED_ROOT,
                public_terminal_bytes=public_terminal_bytes,
            )
            terminal = outcome.terminal
            positive_assertion = False
            if args.require_positive:
                assert_openrouter_v3_positive(
                    protected_state_root=OPENROUTER_V3_PROTECTED_ROOT,
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
        public_terminal_bytes = _read_bounded_regular(
            terminal_path, maximum_bytes=2 * 1024 * 1024
        )
        disposition = classify_openrouter_v3_outcome(
            protected_state_root=OPENROUTER_V3_PROTECTED_ROOT,
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
        if message.startswith(("OPENROUTER_V3_", "LIVE_", "LIVE_MODE")):
            print(message, file=sys.stderr)
        else:
            print("OPENROUTER_V3_REJECTED", file=sys.stderr)
        return 2


def v3_capability_dispatch(argv: list[str], *, _seal: object) -> int:
    """Bootstrap-only capability dispatch behind a dispatcher-minted seal.

    The public module surface never produces a valid seal; only the sanitized
    stdlib bootstrap entrypoint calls through
    :func:`materialize-phase5-demo-profiles._openrouter_v3_capability_dispatch`,
    which mints its own dispatcher-local token.  Every mutating handler
    additionally re-runs the full process gate before any state change.
    """

    from itda.cli import materialize_phase5_demo_profiles as command

    del _seal  # identity delegated to the application dispatcher
    return command._openrouter_v3_capability_run_from_cli_module(argv)


__all__ = [
    "OpenRouterVerifiedOutcomeV3",
    "V3_CAPABILITY_COMMANDS",
    "V3_PUBLIC_COMMANDS",
    "assert_openrouter_v3_positive",
    "build_public_parser",
    "classify_openrouter_v3_outcome",
    "execute_openrouter_v3_production",
    "main",
    "validate_v3_secret_shape",
    "verify_openrouter_v3_outcome",
]
