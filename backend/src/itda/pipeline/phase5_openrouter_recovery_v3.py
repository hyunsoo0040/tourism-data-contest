"""Provider-free OpenRouter r3 recovery durable state, scheduler, and seams.

Fully disjoint from the v1/v2 ``phase5_openrouter_recovery`` modules: no
subclass, alias, or shared durable-state type.  The segmented durable store
persists operation-discriminated ledger entries (RESERVE / DISPATCH / COMMIT
/ RECOVER_UNRESOLVED) with hash-linked sequences and per-entry self digests;
attempts are outcome-discriminated; reconciliation is conservative with a
hard no-resend guarantee.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import threading
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import cast

import httpx

from itda.cli.freeze_preview import _rename_noreplace_at, open_directory_chain_no_follow
from itda.contracts.phase5_openrouter_recovery_v3 import (
    ATTEMPT_OUTCOMES_V3,
    OPENROUTER_V3_CLAIM_SCHEMA,
    OPENROUTER_V3_DISPATCH_SCHEMA,
    OPENROUTER_V3_FIRST_PASS_COUNT,
    OPENROUTER_V3_JOURNAL_ENTRY_SCHEMA,
    OPENROUTER_V3_MAX_ATTEMPTS,
    OPENROUTER_V3_MAX_RETRIES,
    OPENROUTER_V3_RECOVERY_AUTHORITY_ID,
    OPENROUTER_V3_RESERVATION_MICRO_USD,
    OPENROUTER_V3_SNAPSHOT_SHA256,
    OpenRouterApprovalBindingV3,
    OpenRouterClaimV3,
    OpenRouterProtectedStateDescriptorV3,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_V3_TEST_ROOT_MARKERS = ("/tmp/", "/private/tmp/", "/var/folders/")


class OpenRouterCapabilityErrorV3(RuntimeError):
    """Secret-safe openrouter r3 execution rejection."""


def _require_digest(value: object, name: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def require_fixed_openrouter_v3_paths(
    *,
    request_output: Path | None = None,
    protected_root: Path | None = None,
    terminal_output: Path | None = None,
) -> tuple[Path, Path, Path]:
    """Accept only fixed r3/v3 coordinates without stat/open/list access."""

    from itda.contracts.phase5_openrouter_recovery_v3_paths import (
        OPENROUTER_V3_PROTECTED_ROOT,
        OPENROUTER_V3_PUBLIC_REQUEST_PATH,
        OPENROUTER_V3_TERMINAL_OUTPUT,
    )

    request = OPENROUTER_V3_PUBLIC_REQUEST_PATH if request_output is None else request_output
    protected = OPENROUTER_V3_PROTECTED_ROOT if protected_root is None else protected_root
    terminal = OPENROUTER_V3_TERMINAL_OUTPUT if terminal_output is None else terminal_output
    if Path(os.path.abspath(os.fspath(request))) != OPENROUTER_V3_PUBLIC_REQUEST_PATH:
        raise PermissionError("OPENROUTER_V3_REQUEST_PATH_NOT_FIXED")
    if Path(os.path.abspath(os.fspath(protected))) != OPENROUTER_V3_PROTECTED_ROOT:
        raise PermissionError("OPENROUTER_V3_PROTECTED_PATH_NOT_FIXED")
    if Path(os.path.abspath(os.fspath(terminal))) != OPENROUTER_V3_TERMINAL_OUTPUT:
        raise PermissionError("OPENROUTER_V3_TERMINAL_PATH_NOT_FIXED")
    return request, protected, terminal


# ---------------------------------------------------------------------------
# Scheduler: exact 24 first passes before at most 6 retries, concurrency 1.
# ---------------------------------------------------------------------------


class OpenRouterSchedulerV3:
    """24 first passes then at most six retries; one retry per place."""

    def __init__(self, place_ids: Sequence[str]) -> None:
        self._place_ids = tuple(place_ids)
        if len(self._place_ids) != 24 or len(set(self._place_ids)) != 24:
            raise ValueError("openrouter v3 scheduler requires 24 unique places")
        self._first_pass_done = False
        self._first_pass_dispatches = 0
        self._dispatched = 0
        self._retry_places: tuple[str, ...] = ()

    @property
    def attempt_count(self) -> int:
        return self._dispatched

    def first_pass(self) -> tuple[str, ...]:
        if self._first_pass_done:
            raise RuntimeError("openrouter v3 first pass already consumed")
        self._first_pass_done = True
        return self._place_ids

    def record_dispatched(self, place_id: str, *, is_retry: bool) -> None:
        self._dispatched += 1
        if not is_retry:
            self._first_pass_dispatches += 1

    def retry_order(self, retryable_places: Sequence[str]) -> tuple[str, ...]:
        if not self._first_pass_done:
            raise RuntimeError(
                "openrouter v3 retries require the exact 24 first passes dispatched"
            )
        if self._first_pass_dispatches < OPENROUTER_V3_FIRST_PASS_COUNT:
            raise RuntimeError(
                "openrouter v3 retries require all 24 first passes dispatched"
            )
        requested = tuple(retryable_places)
        if self._retry_places:
            raise RuntimeError("openrouter v3 retry plan already sealed")
        if (
            len(requested) > OPENROUTER_V3_MAX_RETRIES
            or len(set(requested)) != len(requested)
        ):
            raise RuntimeError("openrouter v3 retry budget exhausted")
        if requested != tuple(sorted(requested)):
            raise RuntimeError("openrouter v3 retry order is not canonical")
        if any(place not in self._place_ids for place in requested):
            raise RuntimeError("openrouter v3 retry place is not in first-pass inventory")
        projected = self._dispatched + len(requested)
        if projected > OPENROUTER_V3_MAX_ATTEMPTS:
            raise RuntimeError("openrouter v3 attempt budget exhausted")
        self._retry_places = requested
        return requested

    def classify_retry(
        self,
        *,
        error: BaseException | str | None = None,
        status_code: int | None = None,
    ) -> bool:
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            OPENROUTER_V3_RETRYABLE_HTTP_STATUSES,
            OPENROUTER_V3_RETRYABLE_TRANSPORT_NAMES,
        )

        if status_code is not None:
            return status_code in OPENROUTER_V3_RETRYABLE_HTTP_STATUSES
        name = type(error).__name__ if not isinstance(error, str) else error
        return name in OPENROUTER_V3_RETRYABLE_TRANSPORT_NAMES


# ---------------------------------------------------------------------------
# Durable segmented store.
# ---------------------------------------------------------------------------

_STORE_FILE_NAMES = {
    "approval": "approval.json",
    "claim": "claim.json",
    "ledger": "ledger",
    "journal": "journal",
    "attempts": "attempts",
    "reconciliation": "reconciliation",
    "raw": "raw-evidence",
    "profiles": "profiles",
    "generation": "generation.json",
    "terminal": "terminal.json",
}


def _canonical_tmp_spelling(target: Path) -> Path:
    text = str(target)
    if text.startswith("/tmp/") or text == "/tmp":
        return Path("/private/tmp") / Path(*target.parts[2:])
    if text.startswith("/var/") or text == "/var":
        return Path("/private/var") / Path(*target.parts[2:])
    return target


class OpenRouterProtectedStateLayoutV3:
    """Create-only private root layout (dirs 0700, files 0600, single link)."""

    def __init__(self, root: Path) -> None:
        if not root.is_absolute():
            raise PermissionError("OPENROUTER_V3_LAYOUT_ROOT_NOT_ABSOLUTE")
        self._root = _canonical_tmp_spelling(root)

    def create(self) -> dict[str, object]:
        """Create the exact layout once; any pre-existing entry fails closed."""

        created_files: dict[str, object] = {}
        created_dirs: dict[str, object] = {}
        try:
            root_fd = open_directory_chain_no_follow(self._root, create=True)
        except (NotADirectoryError, ValueError) as error:
            raise PermissionError("OPENROUTER_V3_LAYOUT_ROOT_INVALID") from error
        try:
            metadata = os.fstat(root_fd)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o700
                or metadata.st_uid != os.getuid()
            ):
                raise PermissionError("OPENROUTER_V3_LAYOUT_ROOT_INVALID")
            for key in (
                "ledger",
                "journal",
                "attempts",
                "reconciliation",
                "raw",
                "profiles",
            ):
                name = _STORE_FILE_NAMES[key]
                try:
                    os.mkdir(name, mode=0o700, dir_fd=root_fd)
                except FileExistsError as error:
                    raise FileExistsError(name) from error
                fd = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=root_fd,
                )
                try:
                    child_metadata = os.fstat(fd)
                    if not stat.S_ISDIR(child_metadata.st_mode) or stat.S_IMODE(
                        child_metadata.st_mode
                    ) != 0o700:
                        raise PermissionError("OPENROUTER_V3_LAYOUT_DIR_MODE_INVALID")
                finally:
                    os.close(fd)
                created_dirs[name] = child_metadata
            os.fsync(root_fd)
        finally:
            os.close(root_fd)
        return {"root": metadata, "files": created_files, "dirs": created_dirs}


class OpenRouterDurableAuthorityStateV3:
    """Segmented restart-safe authority over approval, claim, ledger, journal.

    Write discipline mirrors Fresh24 semantics without sharing its types:
    component-wise no-follow opens, create-only staging renames, fsync before
    commit, canonical JSONL, and an EXACT-ZERO amount on every ledger event.
    Every ledger read re-verifies sequence continuity, predecessor digests,
    and each entry's self digest — tampering fails closed.
    """

    _MAX_STATE_BYTES = 8 * 1024 * 1024

    def __init__(self, descriptor: OpenRouterProtectedStateDescriptorV3) -> None:
        self._descriptor = descriptor
        root = Path(descriptor.state_root)
        if not root.is_absolute():
            raise PermissionError("OPENROUTER_V3_PROTECTED_ROOT_NOT_LEXICAL")
        self._root = root
        self._names = dict(_STORE_FILE_NAMES)
        self._lock = threading.RLock()

    @classmethod
    def from_root_text(cls, state_root: str) -> OpenRouterDurableAuthorityStateV3:
        """Construct over a caller-supplied SYNTHETIC or fixed coordinate.

        The production CLI passes only the frozen import-time protected-root
        constant; tests pass isolated temporary roots.  Any path that lexically
        aliases the production r3 coordinate (equality, descendant, or symlink
        alias) is rejected unless it IS the exact fixed constant.
        """

        from itda.contracts.phase5_openrouter_recovery_v3_paths import (
            OPENROUTER_V3_PROTECTED_ROOT,
        )

        candidate = Path(os.path.abspath(state_root))
        if candidate != OPENROUTER_V3_PROTECTED_ROOT:
            # Late import: the alias guard lives at module bottom next to the
            # mock seam it protects.
            _reject_v3_production_root_alias(candidate)
        return cls(
            OpenRouterProtectedStateDescriptorV3.from_root(state_root=str(candidate))
        )

    def read_generation_bytes(self) -> bytes:
        root_fd = self._open_root(create=False)
        try:
            return self._read_regular_bytes(root_fd, self._names["generation"])
        finally:
            os.close(root_fd)

    @property
    def descriptor(self) -> OpenRouterProtectedStateDescriptorV3:
        return self._descriptor

    # ------------------------------------------------------------------ roots

    def _open_root(self, *, create: bool) -> int:
        target = _canonical_tmp_spelling(self._root)
        descriptor_fd = open_directory_chain_no_follow(target, create=create)
        try:
            metadata = os.fstat(descriptor_fd)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o700
                or metadata.st_uid != os.getuid()
            ):
                raise PermissionError("OPENROUTER_V3_PROTECTED_ROOT_NOT_PRIVATE")
        except BaseException:
            os.close(descriptor_fd)
            raise
        return descriptor_fd

    def _open_private_dir(self, parent: int, name: str) -> int:
        open_flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            child = os.open(name, open_flags, dir_fd=parent)
        except FileNotFoundError:
            # mkdir is the only portable create-atomic directory primitive
            # here (O_CREAT|O_DIRECTORY raises EINVAL on darwin).
            with suppress(FileExistsError):
                os.mkdir(name, mode=0o700, dir_fd=parent)
            os.fsync(parent)
            child = os.open(name, open_flags, dir_fd=parent)
        metadata = os.fstat(child)
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
            os.close(child)
            raise PermissionError("OPENROUTER_V3_DIRECTORY_INVALID")
        return child

    def _open_existing_private_dir(self, parent: int, name: str) -> int:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        child = os.open(name, flags, dir_fd=parent)
        metadata = os.fstat(child)
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
            os.close(child)
            raise PermissionError("OPENROUTER_V3_DIRECTORY_INVALID")
        return child

    def _exists(self, directory: int, name: str) -> bool:
        try:
            fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory)
        except FileNotFoundError:
            return False
        os.close(fd)
        return True

    # ------------------------------------------------------------------ files

    def _read_regular_bytes(
        self,
        directory: int,
        name: str,
        *,
        allow_empty: bool = False,
        maximum: int | None = None,
    ) -> bytes:
        limit = maximum if maximum is not None else self._MAX_STATE_BYTES
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory)
        try:
            before = os.fstat(fd)
            valid_size = (
                0 <= before.st_size <= limit if allow_empty else 0 < before.st_size <= limit
            )
            if (
                not stat.S_ISREG(before.st_mode)
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_uid != os.getuid()
                or before.st_nlink != 1
                or not valid_size
            ):
                raise PermissionError("OPENROUTER_V3_FILE_INVALID")
            payload = bytearray()
            while len(payload) < before.st_size:
                chunk = os.read(fd, min(65_536, before.st_size - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
            after = os.fstat(fd)
            if len(payload) != before.st_size or (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_nlink,
                before.st_size,
                before.st_mtime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
            ):
                raise PermissionError("OPENROUTER_V3_FILE_CHANGED")
            return bytes(payload)
        finally:
            os.close(fd)

    @staticmethod
    def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, child in pairs:
            if key in value:
                raise ValueError("openrouter v3 JSON contains duplicate keys")
            value[key] = child
        return value

    @classmethod
    def _parse_canonical_json_object(cls, payload: bytes) -> dict[str, object]:
        value = json.loads(payload, object_pairs_hook=cls._unique_object)
        if not isinstance(value, dict):
            raise ValueError("openrouter v3 JSON must be an object")
        return value

    def _read_canonical_json(self, directory: int, name: str) -> dict[str, object]:
        raw = self._read_regular_bytes(directory, name)
        try:
            value = self._parse_canonical_json_object(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise PermissionError("OPENROUTER_V3_FILE_INVALID") from error
        if canonical_json_bytes(value) != raw:
            raise PermissionError("OPENROUTER_V3_FILE_NOT_CANONICAL")
        return value

    def _publish_create_only(self, directory: int, name: str, payload: bytes) -> None:
        staging_name = f".{name}.stage-{__import__('uuid').uuid4().hex}"
        published = False
        try:
            fd = os.open(
                staging_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory,
            )
            try:
                os.fchmod(fd, 0o600)
                written = 0
                while written < len(payload):
                    count = os.write(fd, payload[written:])
                    if count <= 0:
                        raise OSError("short protected-state write")
                    written += count
                os.fsync(fd)
            finally:
                os.close(fd)
            _rename_noreplace_at(directory, staging_name, directory, name)
            published = True
            os.fsync(directory)
        finally:
            if not published:
                with suppress(FileNotFoundError):
                    os.unlink(staging_name, dir_fd=directory)

    def _publish_or_require_exact(
        self,
        directory: int,
        name: str,
        payload: bytes,
        *,
        allow_empty: bool = False,
    ) -> None:
        try:
            self._publish_create_only(directory, name, payload)
        except FileExistsError:
            existing = self._read_regular_bytes(directory, name, allow_empty=allow_empty)
            if existing != payload:
                raise PermissionError("OPENROUTER_V3_REPLACEMENT_FORBIDDEN") from None

    # ----------------------------------------------------------------- ledger

    def _publish_ledger_entry(self, root_fd: int, entry: Mapping[str, object]) -> None:
        ledger = self._open_private_dir(root_fd, self._names["ledger"])
        try:
            name = f"{int(cast(int, entry['sequence'])):04d}-{str(entry['operation']).lower()}.json"
            self._publish_create_only(ledger, name, canonical_json_bytes(entry))
            os.fsync(ledger)
        finally:
            os.close(ledger)

    def read_ledger_entries(self) -> list[dict[str, object]]:
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            parse_openrouter_ledger_entry_v3,
        )

        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                if not self._exists(root_fd, self._names["ledger"]):
                    return []
                ledger = self._open_existing_private_dir(root_fd, self._names["ledger"])
                try:
                    names = sorted(os.listdir(ledger))
                    entries: list[dict[str, object]] = []
                    previous_digest = "0" * 64
                    for expected_sequence, name in enumerate(names, start=1):
                        match = re.fullmatch(
                            r"(\d{4})-(reserve|dispatch|commit|recover_unresolved)\.json",
                            name,
                        )
                        if match is None or int(match.group(1)) != expected_sequence:
                            raise PermissionError("OPENROUTER_V3_LEDGER_FILENAME_INVALID")
                        value = self._read_canonical_json(ledger, name)
                        try:
                            entry = parse_openrouter_ledger_entry_v3(value)
                        except Exception as error:
                            raise PermissionError("OPENROUTER_V3_LEDGER_ENTRY_DRIFT") from error
                        if (
                            int(entry.sequence) != expected_sequence
                            or str(entry.operation).lower() != match.group(2)
                        ):
                            raise PermissionError("OPENROUTER_V3_LEDGER_SEQUENCE_BROKEN")
                        if str(entry.predecessor_entry_sha256) != previous_digest:
                            raise PermissionError("OPENROUTER_V3_LEDGER_CHAIN_BROKEN")
                        previous_digest = str(entry.entry_sha256)
                        entries.append(value)
                    return entries
                finally:
                    os.close(ledger)
            finally:
                os.close(root_fd)

    def committed_exposure_micro_usd(self) -> int:
        return sum(
            int(entry.get("amount_micro_usd", 0))
            for entry in self.read_ledger_entries()
            if entry.get("operation") in {"COMMIT", "RECOVER_UNRESOLVED"}
        )

    def outcome_counts(self) -> dict[str, int]:
        from itda.contracts.phase5_openrouter_recovery_v3 import parse_openrouter_attempt_v3

        counts = {outcome: 0 for outcome in ATTEMPT_OUTCOMES_V3}
        root_fd = self._open_root(create=False)
        try:
            attempts = self._open_existing_private_dir(root_fd, self._names["attempts"])
            try:
                for name in sorted(os.listdir(attempts)):
                    if re.fullmatch(r"attempt-\d{2}\.json", name) is None:
                        raise PermissionError("OPENROUTER_V3_ATTEMPT_INVENTORY_INVALID")
                    record = self._read_canonical_json(attempts, name)
                    attempt = parse_openrouter_attempt_v3(record)
                    counts[str(attempt.outcome)] += 1
            finally:
                os.close(attempts)
        finally:
            os.close(root_fd)
        return counts

    def journal_inventory_digest(self) -> str:
        root_fd = self._open_root(create=False)
        try:
            journal = self._open_existing_private_dir(root_fd, self._names["journal"])
            try:
                entries: list[dict[str, str]] = []
                for directory_name in sorted(os.listdir(journal)):
                    if re.fullmatch(r"attempt-\d{2}", directory_name) is None:
                        raise PermissionError("OPENROUTER_V3_JOURNAL_FILENAME_UNRECOGNIZED")
                    directory = self._open_existing_private_dir(journal, directory_name)
                    try:
                        for marker_name in sorted(os.listdir(directory)):
                            blob = self._read_regular_bytes(directory, marker_name)
                            entries.append(
                                {
                                    "name": f"{directory_name}/{marker_name}",
                                    "sha256": hashlib.sha256(blob).hexdigest(),
                                }
                            )
                    finally:
                        os.close(directory)
                return canonical_sha256(entries)
            finally:
                os.close(journal)
        finally:
            os.close(root_fd)

    def ledger_segment_sha256(self) -> str:
        return canonical_sha256(self.read_ledger_entries())

    # --------------------------------------------------------------- approval

    def install_approval(
        self,
        approval: OpenRouterApprovalBindingV3,
        *,
        request_artifact: Mapping[str, object],
    ) -> dict[str, object]:
        self._validate_approval(approval)
        expected_artifact_digest = request_artifact.get("request_artifact_sha256")
        if (
            not isinstance(expected_artifact_digest, str)
            or not _DIGEST.fullmatch(expected_artifact_digest)
            or expected_artifact_digest != approval.request_artifact_sha256
        ):
            raise PermissionError("OPENROUTER_V3_APPROVAL_ARTIFACT_MISMATCH")
        with self._lock:
            root_fd = self._open_root(create=True)
            try:
                if self._exists(root_fd, self._names["claim"]):
                    raise PermissionError("OPENROUTER_V3_ALREADY_CLAIMED")
                self._publish_or_require_exact(
                    root_fd,
                    self._names["approval"],
                    canonical_json_bytes(approval.model_dump(mode="json")),
                )
                os.fsync(root_fd)
            finally:
                os.close(root_fd)
        return {
            "schema_version": "itda.phase5-openrouter-approval-status.v3",
            "status": "APPROVED_UNCLAIMED",
            "authority_id": approval.authority_id,
            "approval_sha256": approval.approval_sha256,
            "claimed": False,
        }

    def read_approval(self) -> OpenRouterApprovalBindingV3:
        root_fd = self._open_root(create=False)
        try:
            approval = OpenRouterApprovalBindingV3.model_validate(
                self._read_canonical_json(root_fd, self._names["approval"])
            )
            self._validate_approval(approval)
            return approval
        finally:
            os.close(root_fd)

    def _validate_approval(self, approval: OpenRouterApprovalBindingV3) -> None:
        if approval.authority_id != self._descriptor.authority_id:
            raise PermissionError("OPENROUTER_V3_APPROVAL_AUTHORITY_MISMATCH")
        if approval.protected_state_sha256 != self._descriptor.protected_state_sha256:
            raise PermissionError("OPENROUTER_V3_APPROVAL_DESCRIPTOR_MISMATCH")

    # ------------------------------------------------------------------ claim

    def claim_once(self, *, request_artifact: Mapping[str, object]) -> OpenRouterClaimV3:
        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                approval = OpenRouterApprovalBindingV3.model_validate(
                    self._read_canonical_json(root_fd, self._names["approval"])
                )
                self._validate_approval(approval)
                artifact_digest = request_artifact.get("request_artifact_sha256")
                if (
                    not isinstance(artifact_digest, str)
                    or not _DIGEST.fullmatch(artifact_digest)
                    or artifact_digest != approval.request_artifact_sha256
                ):
                    raise PermissionError("OPENROUTER_V3_STALE_APPROVAL")
                claim_fields = {
                    "schema_version": OPENROUTER_V3_CLAIM_SCHEMA,
                    "authority_id": approval.authority_id,
                    "request_artifact_sha256": approval.request_artifact_sha256,
                    "request_file_sha256": approval.request_file_sha256,
                    "approval_sha256": approval.approval_sha256,
                    "protected_state_sha256": approval.protected_state_sha256,
                    "predecessor_consumption_sha256": (
                        approval.predecessor_consumption_sha256
                    ),
                }
                claim = OpenRouterClaimV3.model_validate(
                    {**claim_fields, "claim_sha256": canonical_sha256(claim_fields)}
                )
                try:
                    self._publish_create_only(
                        root_fd,
                        self._names["claim"],
                        canonical_json_bytes(claim.model_dump(mode="json")),
                    )
                except FileExistsError as error:
                    raise PermissionError("OPENROUTER_V3_ALREADY_CLAIMED") from error
                os.fsync(root_fd)
                return claim
            finally:
                os.close(root_fd)

    def read_claim(self) -> OpenRouterClaimV3:
        root_fd = self._open_root(create=False)
        try:
            if not self._exists(root_fd, self._names["claim"]):
                raise PermissionError("OPENROUTER_V3_CLAIM_INVALID")
            return OpenRouterClaimV3.model_validate(
                self._read_canonical_json(root_fd, self._names["claim"])
            )
        finally:
            os.close(root_fd)

    def _require_exact_claim(self, *, claim: OpenRouterClaimV3) -> OpenRouterApprovalBindingV3:
        root_fd = self._open_root(create=False)
        try:
            if not self._exists(root_fd, self._names["claim"]):
                raise PermissionError("OPENROUTER_V3_CLAIM_INVALID")
            persisted = OpenRouterClaimV3.model_validate(
                self._read_canonical_json(root_fd, self._names["claim"])
            )
            approval = OpenRouterApprovalBindingV3.model_validate(
                self._read_canonical_json(root_fd, self._names["approval"])
            )
        finally:
            os.close(root_fd)
        if persisted != claim or claim.approval_sha256 != approval.approval_sha256:
            raise PermissionError("OPENROUTER_V3_CLAIM_INVALID")
        return approval

    # ---------------------------------------------------------------- reserve

    def reserve_once(
        self, *, claim: OpenRouterClaimV3, place_id: str, request_sha256: str
    ) -> int:
        """Durably append the zero-amount claim-bound RESERVE entry.

        A place whose prior attempt settled RECOVER_UNRESOLVED can never be
        reserved again inside this run: the recovery row closes the attempt
        and a second reservation would imply a resend.
        """

        approval = self._require_exact_claim(claim=claim)
        _require_digest(request_sha256, "request digest")
        entries_snapshot = self.read_ledger_entries()
        attempt_number = (
            sum(1 for row in entries_snapshot if row.get("operation") == "RESERVE") + 1
        )
        if attempt_number > OPENROUTER_V3_MAX_ATTEMPTS:
            raise RuntimeError("OPENROUTER_V3_ATTEMPT_BUDGET_EXHAUSTED")
        recovered_places = {
            str(row.get("place_id"))
            for row in entries_snapshot
            if row.get("operation") == "RECOVER_UNRESOLVED"
        }
        if place_id in recovered_places:
            raise PermissionError("OPENROUTER_V3_RESEND_AFTER_RECOVERY_FORBIDDEN")
        prior = [
            row
            for row in entries_snapshot
            if row.get("operation") == "RESERVE"
            and row.get("request_sha256") == request_sha256
            and row.get("place_id") == place_id
        ]
        if len(prior) >= 1:
            raise PermissionError("OPENROUTER_V3_RESERVATION_DUPLICATE")
        reservation_evidence = {
            "authority_id": claim.authority_id,
            "attempt_number": attempt_number,
            "place_id": place_id,
            "request_sha256": request_sha256,
            "claim_sha256": str(claim.claim_sha256),
            "amount_micro_usd": 0,
        }
        entry_fields = {
            "segment": "ATTEMPTS",
            "sequence": len(entries_snapshot) + 1,
            "operation": "RESERVE",
            "attempt_number": attempt_number,
            "amount_micro_usd": OPENROUTER_V3_RESERVATION_MICRO_USD,
            "price_status": "EXACT_ZERO",
            "place_id": place_id,
            "request_sha256": request_sha256,
            "claim_sha256": claim.claim_sha256,
            "evidence_kind": "RESERVATION",
            "required_evidence_sha256": canonical_sha256(reservation_evidence),
            "predecessor_entry_sha256": (
                str(entries_snapshot[-1]["entry_sha256"]) if entries_snapshot else "0" * 64
            ),
        }
        entry = self._build_ledger_entry(entry_fields)
        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                current_entries = self.read_ledger_entries()
                if tuple(canonical_json_bytes(row) for row in current_entries) != tuple(
                    canonical_json_bytes(row) for row in entries_snapshot
                ):
                    raise PermissionError("OPENROUTER_V3_RESERVATION_RACE_INVALID")
                self._publish_ledger_entry(root_fd, entry)
                os.fsync(root_fd)
            finally:
                os.close(root_fd)
        del approval
        return attempt_number

    @staticmethod
    def _build_ledger_entry(fields: Mapping[str, object]) -> dict[str, object]:
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            build_openrouter_ledger_entry_v3,
        )

        validated = build_openrouter_ledger_entry_v3(fields)
        return cast(dict[str, object], validated.model_dump(mode="json"))

    # --------------------------------------------------------------- dispatch

    def record_dispatch(
        self,
        *,
        claim: OpenRouterClaimV3,
        place_id: str,
        request_sha256: str,
        attempt_number: int,
    ) -> int:
        """Ledger DISPATCH row plus create-only journal marker before secret."""

        approval = self._require_exact_claim(claim=claim)
        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                entries = self.read_ledger_entries()
                marker_fields = {
                    "schema_version": OPENROUTER_V3_JOURNAL_ENTRY_SCHEMA,
                    "authority_id": approval.authority_id,
                    "phase": "DISPATCH_PREPARED",
                    "attempt_number": attempt_number,
                    "place_id": place_id,
                    "request_sha256": request_sha256,
                    "claim_sha256": claim.claim_sha256,
                }
                marker = OpenRouterJournalMarker(marker_fields).payload()
                journal = self._open_private_dir(root_fd, self._names["journal"])
                attempt_journal = self._open_private_dir(
                    journal, f"attempt-{attempt_number:02d}"
                )
                try:
                    self._publish_create_only(
                        attempt_journal,
                        "dispatch-prepared.json",
                        canonical_json_bytes(marker),
                    )
                    os.fsync(attempt_journal)
                finally:
                    os.close(attempt_journal)
                    os.close(journal)
                dispatch_fields = {
                    "segment": "ATTEMPTS",
                    "sequence": len(entries) + 1,
                    "operation": "DISPATCH",
                    "attempt_number": attempt_number,
                    "amount_micro_usd": OPENROUTER_V3_RESERVATION_MICRO_USD,
                    "price_status": "EXACT_ZERO",
                    "place_id": place_id,
                    "request_sha256": request_sha256,
                    "claim_sha256": claim.claim_sha256,
                    "evidence_kind": "DISPATCH_PREPARED",
                    "required_evidence_sha256": str(marker["entry_sha256"]),
                    "predecessor_entry_sha256": (
                        str(entries[-1]["entry_sha256"]) if entries else "0" * 64
                    ),
                }
                self._publish_ledger_entry(
                    root_fd, self._build_ledger_entry(dispatch_fields)
                )
                os.fsync(root_fd)
                return attempt_number
            finally:
                os.close(root_fd)

    def record_client_constructed(
        self,
        *,
        claim: OpenRouterClaimV3,
        place_id: str,
        attempt_number: int,
    ) -> None:
        """Locally confirmable CLIENT_CONSTRUCTED fact, create-only, fsynced."""

        self._require_exact_claim(claim=claim)
        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                journal = self._open_existing_private_dir(root_fd, self._names["journal"])
                attempt_journal = self._open_existing_private_dir(
                    journal, f"attempt-{attempt_number:02d}"
                )
                try:
                    marker = OpenRouterJournalMarker(
                        {
                            "schema_version": OPENROUTER_V3_JOURNAL_ENTRY_SCHEMA,
                            "authority_id": OPENROUTER_V3_RECOVERY_AUTHORITY_ID,
                            "phase": "CLIENT_CONSTRUCTED",
                            "attempt_number": attempt_number,
                            "place_id": place_id,
                            "request_sha256": _marker_request_fallback(),
                            "claim_sha256": claim.claim_sha256,
                        },
                        client_fact=True,
                    )
                    self._publish_create_only(
                        attempt_journal,
                        "client-constructed.json",
                        canonical_json_bytes(marker.payload()),
                    )
                    os.fsync(attempt_journal)
                finally:
                    os.close(attempt_journal)
                    os.close(journal)
                os.fsync(root_fd)
            finally:
                os.close(root_fd)

    def record_send_boundary(
        self,
        *,
        claim: OpenRouterClaimV3,
        place_id: str,
        attempt_number: int,
    ) -> None:
        """Send-boundary marker BEFORE stream(): MAY_HAVE_STARTED, never SENT."""

        self._require_exact_claim(claim=claim)
        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                journal = self._open_existing_private_dir(root_fd, self._names["journal"])
                attempt_journal = self._open_existing_private_dir(
                    journal, f"attempt-{attempt_number:02d}"
                )
                try:
                    marker = OpenRouterJournalMarker(
                        {
                            "schema_version": OPENROUTER_V3_DISPATCH_SCHEMA,
                            "authority_id": OPENROUTER_V3_RECOVERY_AUTHORITY_ID,
                            "phase": "SEND_ATTEMPT_BOUNDARY_REACHED",
                            "attempt_number": attempt_number,
                            "place_id": place_id,
                            "request_sha256": _marker_request_fallback(),
                            "claim_sha256": claim.claim_sha256,
                        },
                        send_fact=True,
                    )
                    self._publish_create_only(
                        attempt_journal,
                        "send-boundary.json",
                        canonical_json_bytes(marker.payload()),
                    )
                    os.fsync(attempt_journal)
                finally:
                    os.close(attempt_journal)
                    os.close(journal)
                os.fsync(root_fd)
            finally:
                os.close(root_fd)

    # ---------------------------------------------------------------- evidence

    def persist_attempt_evidence(
        self,
        *,
        claim: OpenRouterClaimV3,
        place_id: str,
        request_sha256: str,
        attempt_number: int,
        outcome: str,
        status_code: int | None = None,
        response_body: bytes | None = None,
        transport_class: str | None = None,
        failure_code: str | None = None,
    ) -> str:
        """Persist ONE outcome-discriminated attempt record.

        CREDENTIAL_RESPONSE_STRIPPED stores no original body length/digest/
        raw bytes — only the fixed strip marker.  The returned digest binds
        the attempt's outcome preimage for the COMMIT row.
        """

        if outcome not in ATTEMPT_OUTCOMES_V3:
            raise PermissionError("OPENROUTER_V3_OUTCOME_UNKNOWN")
        if outcome == "CREDENTIAL_RESPONSE_STRIPPED" and response_body is not None:
            raise PermissionError("OPENROUTER_V3_STRIPPED_EVIDENCE_MUST_BE_EMPTY")
        approval = self._require_exact_claim(claim=claim)
        fields: dict[str, object] = {
            "attempt_number": attempt_number,
            "place_id": place_id,
            "request_sha256": request_sha256,
            "claim_sha256": claim.claim_sha256,
            "outcome": outcome,
        }
        if outcome == "HTTP_RESPONSE":
            if response_body is None or status_code is None:
                raise PermissionError("OPENROUTER_V3_HTTP_EVIDENCE_INCOMPLETE")
            response_sha256 = hashlib.sha256(response_body).hexdigest()
            raw_manifest = {
                "name": f"response-{attempt_number:02d}.bin",
                "length": len(response_body),
                "sha256": response_sha256,
            }
            fields.update(
                {
                    "status_code": status_code,
                    "response_length": len(response_body),
                    "response_sha256": response_sha256,
                    "raw_evidence_sha256": canonical_sha256(raw_manifest),
                }
            )
        elif outcome == "TRANSPORT_ERROR":
            if transport_class is None:
                raise PermissionError("OPENROUTER_V3_TRANSPORT_EVIDENCE_INCOMPLETE")
            from itda.contracts.phase5_openrouter_recovery_v3 import (
                OPENROUTER_V3_RETRYABLE_TRANSPORT_NAMES,
            )

            fields.update(
                {
                    "transport_class": transport_class,
                    "retry_classification": (
                        "RETRYABLE"
                        if transport_class in OPENROUTER_V3_RETRYABLE_TRANSPORT_NAMES
                        else "FINAL"
                    ),
                }
            )
        elif outcome == "CREDENTIAL_RESPONSE_STRIPPED":
            if status_code is None:
                raise PermissionError("OPENROUTER_V3_STRIPPED_STATUS_REQUIRED")
            fields.update(
                {
                    "status_code": status_code,
                    "strip_marker": "CREDENTIAL_RESPONSE_STRIPPED",
                }
            )
        else:
            if failure_code != "OPENROUTER_SECRET_UNAVAILABLE":
                raise PermissionError("OPENROUTER_V3_LOCAL_FAILURE_INVALID")
            fields.update(
                {
                    "failure_code": failure_code,
                    "secret_read": False,
                    "client_constructed": False,
                    "send_boundary_reached": False,
                    "network_attempted": False,
                }
            )
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            build_openrouter_attempt_v3,
        )

        attempt = build_openrouter_attempt_v3(fields)
        attempt_payload = canonical_json_bytes(attempt.model_dump(mode="json"))
        with self._lock:
            root_fd = self._open_root(create=False)
            attempts_dir = self._open_private_dir(root_fd, self._names["attempts"])
            raw_dir = self._open_private_dir(root_fd, self._names["raw"])
            try:
                if outcome == "HTTP_RESPONSE":
                    assert response_body is not None
                    self._publish_create_only(
                        raw_dir,
                        f"response-{attempt_number:02d}.bin",
                        response_body,
                    )
                self._publish_create_only(
                    attempts_dir,
                    f"attempt-{attempt_number:02d}.json",
                    attempt_payload,
                )
                os.fsync(raw_dir)
                os.fsync(attempts_dir)
            except FileExistsError as error:
                raise PermissionError("OPENROUTER_V3_ATTEMPT_REPLACEMENT_FORBIDDEN") from error
            finally:
                os.close(raw_dir)
                os.close(attempts_dir)
                os.close(root_fd)
        del approval
        return str(attempt.outcome_sha256)

    def commit_reservation(
        self,
        *,
        claim: OpenRouterClaimV3,
        place_id: str,
        request_sha256: str,
        attempt_number: int,
        evidence_sha256: str,
    ) -> None:
        if not isinstance(evidence_sha256, str) or not _DIGEST.fullmatch(evidence_sha256):
            raise PermissionError("OPENROUTER_V3_EVIDENCE_DIGEST_REQUIRED")
        self._require_exact_claim(claim=claim)
        with self._lock:
            root_fd = self._open_root(create=False)
            attempts_dir = self._open_existing_private_dir(
                root_fd, self._names["attempts"]
            )
            try:
                attempt_record = self._read_canonical_json(
                    attempts_dir, f"attempt-{attempt_number:02d}.json"
                )
                if attempt_record.get("outcome_sha256") != evidence_sha256:
                    raise PermissionError("OPENROUTER_V3_EVIDENCE_DIGEST_INVALID")
                if (
                    attempt_record.get("place_id") != place_id
                    or attempt_record.get("request_sha256") != request_sha256
                ):
                    raise PermissionError("OPENROUTER_V3_EVIDENCE_LINEAGE_INVALID")
                entries = self.read_ledger_entries()
                matching = [
                    row
                    for row in entries
                    if row.get("operation") == "RESERVE"
                    and row.get("request_sha256") == request_sha256
                    and row.get("attempt_number") == attempt_number
                ]
                already_settled = any(
                    row.get("operation") in {"COMMIT", "RECOVER_UNRESOLVED"}
                    and row.get("request_sha256") == request_sha256
                    and row.get("attempt_number") == attempt_number
                    for row in entries
                )
                if len(matching) != 1 or already_settled:
                    raise PermissionError("OPENROUTER_V3_COMMIT_ORDER_INVALID")
                commit_fields = {
                    "segment": "ATTEMPTS",
                    "sequence": len(entries) + 1,
                    "operation": "COMMIT",
                    "attempt_number": attempt_number,
                    "amount_micro_usd": OPENROUTER_V3_RESERVATION_MICRO_USD,
                    "price_status": "EXACT_ZERO",
                    "place_id": place_id,
                    "request_sha256": request_sha256,
                    "claim_sha256": claim.claim_sha256,
                    "evidence_kind": "ATTEMPT_OUTCOME",
                    "required_evidence_sha256": evidence_sha256,
                    "predecessor_entry_sha256": (
                        str(entries[-1]["entry_sha256"]) if entries else "0" * 64
                    ),
                }
                self._publish_ledger_entry(
                    root_fd, self._build_ledger_entry(commit_fields)
                )
                os.fsync(root_fd)
            finally:
                os.close(attempts_dir)
                os.close(root_fd)

    # ------------------------------------------------------------- generation

    def publish_generation(self, *, generation: Mapping[str, object]) -> str:
        payload = dict(generation)
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            OPENROUTER_V3_GENERATION_SCHEMA,
        )

        if payload.get("schema_version") != OPENROUTER_V3_GENERATION_SCHEMA:
            raise ValueError("openrouter v3 generation schema drifted")
        serialized = canonical_json_bytes(payload)
        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                self._publish_create_only(root_fd, self._names["generation"], serialized)
            except FileExistsError as error:
                existing = self._read_regular_bytes(root_fd, self._names["generation"])
                if existing != serialized:
                    raise PermissionError(
                        "OPENROUTER_V3_REPLACEMENT_FORBIDDEN"
                    ) from error
            finally:
                os.close(root_fd)
        return hashlib.sha256(serialized).hexdigest()

    def publish_terminal_raw(self, *, payload: bytes) -> None:
        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                self._publish_or_require_exact(root_fd, self._names["terminal"], payload)
            finally:
                os.close(root_fd)

    def publish_terminal(self, *, terminal: Mapping[str, object]) -> None:
        self.publish_terminal_raw(payload=canonical_json_bytes(terminal))

    def list_profile_names(self) -> list[str]:
        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                if not self._exists(root_fd, self._names["profiles"]):
                    return []
                profiles_dir = self._open_existing_private_dir(root_fd, self._names["profiles"])
                try:
                    names = []
                    for name in sorted(os.listdir(profiles_dir)):
                        metadata = os.stat(name, dir_fd=profiles_dir, follow_symlinks=False)
                        if stat.S_ISLNK(metadata.st_mode):
                            raise PermissionError("OPENROUTER_V3_PROFILE_SYMLINK_FORBIDDEN")
                        names.append(name)
                    return names
                finally:
                    os.close(profiles_dir)
            finally:
                os.close(root_fd)

    def read_profile_bytes(self, name: str) -> bytes:
        if not re.fullmatch(r"profile-\d{2}-[A-Za-z0-9_-]{1,160}\.json", name):
            raise PermissionError("OPENROUTER_V3_PROFILE_NAME_INVALID")
        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                profiles_dir = self._open_existing_private_dir(root_fd, self._names["profiles"])
                try:
                    return self._read_regular_bytes(profiles_dir, name)
                finally:
                    os.close(profiles_dir)
            finally:
                os.close(root_fd)

    def publish_profile_evidence(
        self,
        *,
        claim: OpenRouterClaimV3,
        place_id: str,
        request_sha256: str,
        attempt_number: int,
        profile_payload: Mapping[str, object],
    ) -> None:
        payload_bytes = canonical_json_bytes(profile_payload)
        with self._lock:
            root_fd = self._open_root(create=False)
            profiles_dir = self._open_existing_private_dir(root_fd, self._names["profiles"])
            try:
                place_tag = re.sub(r"[^A-Za-z0-9_-]", "_", place_id)[:160]
                name = f"profile-{attempt_number:02d}-{place_tag}.json"
                try:
                    self._publish_create_only(profiles_dir, name, payload_bytes)
                except FileExistsError:
                    existing = self._read_regular_bytes(profiles_dir, name)
                    if existing != payload_bytes:
                        raise PermissionError(
                            "OPENROUTER_V3_PROFILE_REPLACEMENT_FORBIDDEN"
                        ) from None
                os.fsync(profiles_dir)
            finally:
                os.close(profiles_dir)
                os.close(root_fd)

    def read_protected_terminal_bytes(self) -> bytes:
        root_fd = self._open_root(create=False)
        try:
            if not self._exists(root_fd, self._names["terminal"]):
                raise PermissionError("OPENROUTER_V3_PROTECTED_TERMINAL_MISSING")
            return self._read_regular_bytes(root_fd, self._names["terminal"])
        finally:
            os.close(root_fd)

    def ensure_profiles_dir(self) -> None:
        with self._lock:
            root_fd = self._open_root(create=True)
            try:
                fd = os.open(
                    self._names["profiles"],
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=root_fd,
                )
                os.close(fd)
            except FileNotFoundError:
                child = self._open_private_dir(root_fd, self._names["profiles"])
                os.close(child)
            finally:
                os.close(root_fd)

    def ensure_raw_evidence_dir(self) -> None:
        with self._lock:
            root_fd = self._open_root(create=True)
            try:
                fd = os.open(
                    self._names["raw"],
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=root_fd,
                )
                os.close(fd)
            except FileNotFoundError:
                child = self._open_private_dir(root_fd, self._names["raw"])
                os.close(child)
            finally:
                os.close(root_fd)

    def validate_root_inventory(self, *, require_generation: bool = True) -> None:
        expected = set(self._names.values())
        if not require_generation:
            expected.discard(self._names["generation"])
        root_fd = self._open_root(create=False)
        try:
            names = set(os.listdir(root_fd))
            if names != expected:
                raise PermissionError("OPENROUTER_V3_ROOT_INVENTORY_INVALID")
            for name in names:
                metadata = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                if stat.S_ISLNK(metadata.st_mode):
                    raise PermissionError("OPENROUTER_V3_ROOT_SYMLINK_FORBIDDEN")
        finally:
            os.close(root_fd)

    # --------------------------------------------------- inventory validators

    def validate_journal_evidence_inventory(self) -> None:
        entries = self.read_ledger_entries()
        reserves = {
            int(cast(int, row["attempt_number"])): row
            for row in entries
            if row.get("operation") == "RESERVE"
        }
        dispatches = {
            int(cast(int, row["attempt_number"])): row
            for row in entries
            if row.get("operation") == "DISPATCH"
        }
        root_fd = self._open_root(create=False)
        try:
            if not self._exists(root_fd, self._names["journal"]):
                if dispatches:
                    raise PermissionError("OPENROUTER_V3_JOURNAL_MISSING")
                return
            journal = self._open_existing_private_dir(root_fd, self._names["journal"])
            try:
                names = set(os.listdir(journal))
                expected = {f"attempt-{ordinal:02d}" for ordinal in dispatches}
                if names != expected:
                    raise PermissionError("OPENROUTER_V3_JOURNAL_FILENAME_UNRECOGNIZED")
                for ordinal, dispatch in dispatches.items():
                    directory = self._open_existing_private_dir(
                        journal, f"attempt-{ordinal:02d}"
                    )
                    try:
                        marker_names = set(os.listdir(directory))
                        allowed = {
                            "dispatch-prepared.json",
                            "client-constructed.json",
                            "send-boundary.json",
                        }
                        if (
                            "dispatch-prepared.json" not in marker_names
                            or not marker_names <= allowed
                            or (
                                "send-boundary.json" in marker_names
                                and "client-constructed.json" not in marker_names
                            )
                        ):
                            raise PermissionError(
                                "OPENROUTER_V3_JOURNAL_FILENAME_UNRECOGNIZED"
                            )
                        reserve = reserves.get(ordinal)
                        if reserve is None:
                            raise PermissionError("OPENROUTER_V3_JOURNAL_ORPHAN_MARKER")
                        for marker_name in marker_names:
                            record = self._read_canonical_json(directory, marker_name)
                            if (
                                record.get("attempt_number") != ordinal
                                or record.get("claim_sha256") != reserve.get("claim_sha256")
                                or record.get("place_id") != reserve.get("place_id")
                            ):
                                raise PermissionError(
                                    "OPENROUTER_V3_JOURNAL_LINEAGE_INVALID"
                                )
                        dispatch_record = self._read_canonical_json(
                            directory, "dispatch-prepared.json"
                        )
                        if (
                            dispatch.get("required_evidence_sha256")
                            != dispatch_record.get("entry_sha256")
                        ):
                            raise PermissionError(
                                "OPENROUTER_V3_DISPATCH_EVIDENCE_INVALID"
                            )
                    finally:
                        os.close(directory)
            finally:
                os.close(journal)
        finally:
            os.close(root_fd)

    def validate_raw_evidence_inventory(self, *, require_attempt_dirs: bool = False) -> None:
        from itda.contracts.phase5_openrouter_recovery_v3 import (
            parse_openrouter_attempt_v3,
        )

        entries = self.read_ledger_entries()
        reserves = {
            int(cast(int, row["attempt_number"])): row
            for row in entries
            if row.get("operation") == "RESERVE"
        }
        commits = {
            int(cast(int, row["attempt_number"])): row
            for row in entries
            if row.get("operation") == "COMMIT"
        }
        root_fd = self._open_root(create=False)
        try:
            if require_attempt_dirs or commits:
                attempts_dir = self._open_existing_private_dir(
                    root_fd, self._names["attempts"]
                )
                raw_dir = self._open_existing_private_dir(root_fd, self._names["raw"])
            else:
                # A run with zero COMMITs (e.g. FAILED_UNACTIVATED) may have
                # never created the segmented evidence directories; the
                # exact inventory is then the empty set.
                for name in ("attempts", "raw"):
                    if self._exists(root_fd, name):
                        directory = self._open_existing_private_dir(root_fd, name)
                        try:
                            if os.listdir(directory):
                                raise PermissionError(
                                    "OPENROUTER_V3_RAW_INVENTORY_INVALID"
                                )
                        finally:
                            os.close(directory)
                return
            try:
                attempt_names = set(os.listdir(attempts_dir))
                expected_attempts = {
                    f"attempt-{ordinal:02d}.json" for ordinal in commits
                }
                if attempt_names != expected_attempts:
                    raise PermissionError("OPENROUTER_V3_ATTEMPT_INVENTORY_INVALID")
                expected_raw: set[str] = set()
                attempt_records: dict[int, dict[str, object]] = {}
                for ordinal, commit in commits.items():
                    name = f"attempt-{ordinal:02d}.json"
                    record = self._read_canonical_json(attempts_dir, name)
                    attempt = parse_openrouter_attempt_v3(record)
                    if commit.get("required_evidence_sha256") != attempt.outcome_sha256:
                        raise PermissionError("OPENROUTER_V3_COMMIT_EVIDENCE_INVALID")
                    reserve = reserves.get(ordinal)
                    if (
                        reserve is None
                        or record.get("attempt_number") != ordinal
                        or record.get("claim_sha256") != reserve.get("claim_sha256")
                        or record.get("place_id") != reserve.get("place_id")
                        or record.get("request_sha256") != reserve.get("request_sha256")
                    ):
                        raise PermissionError("OPENROUTER_V3_ATTEMPT_LINEAGE_INVALID")
                    attempt_records[ordinal] = record
                    if record.get("outcome") == "HTTP_RESPONSE":
                        expected_raw.add(f"response-{ordinal:02d}.bin")
                    elif any(
                        key in record
                        for key in (
                            "response_length",
                            "response_sha256",
                            "raw_evidence_sha256",
                        )
                    ):
                        raise PermissionError("OPENROUTER_V3_STRIPPED_EVIDENCE_TAINTED")
                if set(os.listdir(raw_dir)) != expected_raw:
                    raise PermissionError("OPENROUTER_V3_RAW_INVENTORY_INVALID")
                for name in expected_raw:
                    ordinal = int(name.removeprefix("response-").removesuffix(".bin"))
                    blob = self._read_regular_bytes(raw_dir, name, allow_empty=True)
                    record = attempt_records[ordinal]
                    manifest = {
                        "name": name,
                        "length": len(blob),
                        "sha256": hashlib.sha256(blob).hexdigest(),
                    }
                    if (
                        record.get("response_length") != len(blob)
                        or record.get("response_sha256") != manifest["sha256"]
                        or record.get("raw_evidence_sha256")
                        != canonical_sha256(manifest)
                    ):
                        raise PermissionError("OPENROUTER_V3_RAW_LINEAGE_INVALID")
            finally:
                os.close(raw_dir)
                os.close(attempts_dir)
        finally:
            os.close(root_fd)

    def validate_reconciliation_inventory(self) -> None:
        from itda.contracts.phase5_openrouter_recovery_v3 import OpenRouterReconciliationV3

        entries = self.read_ledger_entries()
        reserves = {
            int(cast(int, row["attempt_number"])): row
            for row in entries
            if row.get("operation") == "RESERVE"
        }
        recovered = {
            int(cast(int, row["attempt_number"])): row
            for row in entries
            if row.get("operation") == "RECOVER_UNRESOLVED"
        }
        root_fd = self._open_root(create=False)
        try:
            reconciliation_dir = self._open_existing_private_dir(
                root_fd, self._names["reconciliation"]
            )
            journal = self._open_existing_private_dir(root_fd, self._names["journal"])
            try:
                expected = {f"attempt-{ordinal:02d}.json" for ordinal in recovered}
                if set(os.listdir(reconciliation_dir)) != expected:
                    raise PermissionError("OPENROUTER_V3_RECONCILIATION_INVENTORY_INVALID")
                for ordinal, recover in recovered.items():
                    name = f"attempt-{ordinal:02d}.json"
                    record = self._read_canonical_json(reconciliation_dir, name)
                    reconciliation = OpenRouterReconciliationV3.model_validate(record)
                    reserve = reserves.get(ordinal)
                    if reserve is None:
                        raise PermissionError("OPENROUTER_V3_RECONCILIATION_ORPHANED")
                    attempt_dir = self._open_existing_private_dir(
                        journal, f"attempt-{ordinal:02d}"
                    )
                    try:
                        markers = [
                            {
                                "name": marker,
                                "sha256": hashlib.sha256(
                                    self._read_regular_bytes(attempt_dir, marker)
                                ).hexdigest(),
                            }
                            for marker in sorted(os.listdir(attempt_dir))
                        ]
                    finally:
                        os.close(attempt_dir)
                    if (
                        reconciliation.claim_sha256 != reserve.get("claim_sha256")
                        or reconciliation.place_id != reserve.get("place_id")
                        or reconciliation.request_sha256 != reserve.get("request_sha256")
                        or reconciliation.reserve_entry_sha256 != reserve.get("entry_sha256")
                        or reconciliation.observed_journal_sha256 != canonical_sha256(markers)
                        or recover.get("required_evidence_sha256")
                        != reconciliation.reconciliation_sha256
                    ):
                        raise PermissionError("OPENROUTER_V3_RECONCILIATION_LINEAGE_INVALID")
            finally:
                os.close(journal)
                os.close(reconciliation_dir)
        finally:
            os.close(root_fd)

    # ------------------------------------------------------------ reconcile

    def reconcile_interrupted(self, *, claim: OpenRouterClaimV3) -> dict[str, object] | None:
        """Close interrupted dispatched exposure conservatively (no resend)."""

        approval = self._require_exact_claim(claim=claim)
        entries = self.read_ledger_entries()
        reserves = [
            row
            for row in entries
            if row.get("operation") == "RESERVE"
            and row.get("claim_sha256") == claim.claim_sha256
        ]
        settled_ids = {
            (
                row.get("place_id"),
                row.get("request_sha256"),
                int(cast(int, row.get("attempt_number", 0))),
            )
            for row in entries
            if row.get("operation") in {"COMMIT", "RECOVER_UNRESOLVED"}
        }
        pending = [
            row
            for row in reserves
            if (
                row.get("place_id"),
                row.get("request_sha256"),
                int(cast(int, row.get("attempt_number", 0))),
            )
            not in settled_ids
        ]
        if not pending:
            return None
        reconciled_phases: list[str] = []
        with self._lock:
            root_fd = self._open_root(create=False)
            reconciliation_dir = self._open_private_dir(
                root_fd, self._names["reconciliation"]
            )
            attempts_dir = self._open_private_dir(root_fd, self._names["attempts"])
            journal = self._open_private_dir(root_fd, self._names["journal"])
            try:
                for row in pending:
                    place_id = str(row.get("place_id"))
                    ordinal = int(cast(int, row.get("attempt_number", 0)))
                    attempt_dir_name = f"attempt-{ordinal:02d}"
                    marker_names: set[str] = set()
                    if self._exists(journal, attempt_dir_name):
                        attempt_journal = self._open_existing_private_dir(
                            journal, attempt_dir_name
                        )
                        try:
                            marker_names = set(os.listdir(attempt_journal))
                            marker_digests = [
                                {
                                    "name": name,
                                    "sha256": hashlib.sha256(
                                        self._read_regular_bytes(attempt_journal, name)
                                    ).hexdigest(),
                                }
                                for name in sorted(marker_names)
                            ]
                        finally:
                            os.close(attempt_journal)
                    else:
                        marker_digests = []
                    if self._exists(attempts_dir, f"attempt-{ordinal:02d}.json"):
                        raise PermissionError(
                            "OPENROUTER_V3_RECONCILIATION_EVIDENCE_UNSETTLED"
                        )
                    dispatched = "dispatch-prepared.json" in marker_names
                    client_marker = "client-constructed.json" in marker_names
                    boundary_marker = "send-boundary.json" in marker_names
                    if boundary_marker and client_marker:
                        phase = "SEND_ATTEMPT_BOUNDARY_REACHED"
                        send_certainty = "SEND_ATTEMPT_MAY_HAVE_STARTED"
                    elif client_marker:
                        phase = "CLIENT_CONSTRUCTED"
                        send_certainty = "UNKNOWN_AFTER_DISPATCH"
                    elif dispatched:
                        phase = "DISPATCH_PREPARED"
                        send_certainty = "NOT_STARTED_CONFIRMED_LOCALLY"
                    else:
                        phase = "RESERVED"
                        send_certainty = "NOT_STARTED_CONFIRMED_LOCALLY"
                    from itda.contracts.phase5_openrouter_recovery_v3 import (
                        OPENROUTER_V3_RECONCILIATION_SCHEMA,
                        OpenRouterReconciliationV3,
                    )

                    reconciliation_fields = {
                        "schema_version": OPENROUTER_V3_RECONCILIATION_SCHEMA,
                        "authority_id": approval.authority_id,
                        "attempt_number": ordinal,
                        "place_id": place_id,
                        "request_sha256": row.get("request_sha256"),
                        "claim_sha256": claim.claim_sha256,
                        "reserve_entry_sha256": row.get("entry_sha256"),
                        "observed_journal_sha256": canonical_sha256(marker_digests),
                        "dispatch_phase": phase,
                        "send_certainty": send_certainty,
                        "client_constructed": client_marker,
                        "send_boundary_reached": boundary_marker,
                        "network_attempted": boundary_marker,
                        "resend_forbidden": True,
                    }
                    reconciliation = OpenRouterReconciliationV3.model_validate(
                        {
                            **reconciliation_fields,
                            "reconciliation_sha256": canonical_sha256(
                                reconciliation_fields
                            ),
                        }
                    )
                    self._publish_create_only(
                        reconciliation_dir,
                        f"attempt-{ordinal:02d}.json",
                        canonical_json_bytes(reconciliation.model_dump(mode="json")),
                    )
                    recover_fields = {
                        "segment": "SETTLEMENTS",
                        "sequence": len(entries) + 1,
                        "operation": "RECOVER_UNRESOLVED",
                        "attempt_number": ordinal,
                        "amount_micro_usd": OPENROUTER_V3_RESERVATION_MICRO_USD,
                        "price_status": "EXACT_ZERO",
                        "place_id": place_id,
                        "request_sha256": row.get("request_sha256"),
                        "claim_sha256": claim.claim_sha256,
                        "evidence_kind": "RECONCILIATION",
                        "required_evidence_sha256": str(
                            reconciliation.reconciliation_sha256
                        ),
                        "predecessor_entry_sha256": (
                            str(entries[-1]["entry_sha256"])
                            if entries
                            else "0" * 64
                        ),
                    }
                    recover_entry = self._build_ledger_entry(recover_fields)
                    self._publish_ledger_entry(root_fd, recover_entry)
                    entries.append(recover_entry)
                    reconciled_phases.append(phase)
                os.fsync(reconciliation_dir)
                os.fsync(root_fd)
            finally:
                os.close(journal)
                os.close(attempts_dir)
                os.close(reconciliation_dir)
                os.close(root_fd)
        if "SEND_ATTEMPT_BOUNDARY_REACHED" in reconciled_phases:
            summary_send = "SEND_ATTEMPT_MAY_HAVE_STARTED"
            summary_client_true = True
        elif "CLIENT_CONSTRUCTED" in reconciled_phases:
            summary_send = "UNKNOWN_AFTER_DISPATCH"
            summary_client_true = True
        else:
            summary_send = "NOT_STARTED_CONFIRMED_LOCALLY"
            summary_client_true = False
        return {
            "status": "DESIGNED_NEGATIVE",
            "reason": "OPENROUTER_V3_INTERRUPTED_EXPOSURE_CONSERVATIVE",
            "recovered_count": len(pending),
            "committed_exposure_micro_usd": self.committed_exposure_micro_usd(),
            "client_constructed": summary_client_true,
            "network_attempted": False,
            "send_certainty": summary_send,
            "lifecycle_mutated": False,
        }


def _marker_request_fallback() -> str:
    """The synthetic request digest used by non-dispatch journal markers.

    Client/send-boundary markers do not carry member-specific requests; the
    inventory validator correlates them by ordinal and claim identity only.
    The all-zero digest makes that explicit instead of inheriting a stale
    value from another field.
    """

    return "0" * 64


class OpenRouterJournalMarker:
    """Typed wrapper building one self-digested journal marker payload."""

    def __init__(
        self,
        fields: Mapping[str, object],
        *,
        client_fact: bool = False,
        send_fact: bool = False,
    ) -> None:
        self._fields = {key: value for key, value in fields.items()}
        self._extra = {
            **({"client_fact": "CLIENT_CONSTRUCTED_CONFIRMED_LOCALLY"} if client_fact else {}),
            **({"send_fact": "SEND_ATTEMPT_MAY_HAVE_STARTED"} if send_fact else {}),
        }

    def payload(self) -> dict[str, object]:
        payload = {**self._fields, **self._extra}
        unsigned = {k: v for k, v in payload.items() if k != "entry_sha256"}
        return {**payload, "entry_sha256": canonical_sha256(unsigned)}


# ---------------------------------------------------------------------------
# Sealed mock transport seam (strictly test-only, temp roots only).
# ---------------------------------------------------------------------------


def _reject_v3_production_root_alias(candidate: Path) -> None:
    from itda.contracts.phase5_openrouter_recovery_v3_paths import (
        OPENROUTER_V3_PROTECTED_ROOT,
    )

    production = Path(os.path.abspath(os.fspath(OPENROUTER_V3_PROTECTED_ROOT)))
    candidate_absolute = Path(os.path.abspath(os.fspath(candidate)))
    if candidate_absolute == production:
        raise PermissionError("OPENROUTER_V3_MOCK_FORBIDS_PRODUCTION_ROOT")
    if production in candidate_absolute.parents:
        raise PermissionError("OPENROUTER_V3_MOCK_FORBIDS_PRODUCTION_ROOT_DESCENDANT")

    # Inspect only existing candidate-side components (synthetic temp state in
    # tests).  Never call resolve/stat/list on the production coordinate.  A
    # symlink component whose lexical target is production or its descendant is
    # rejected before any state constructor can open anything.
    probe = Path(candidate_absolute.anchor)
    for component in candidate_absolute.parts[1:]:
        probe = probe / component
        if probe == production or production in probe.parents:
            raise PermissionError("OPENROUTER_V3_MOCK_FORBIDS_PRODUCTION_ROOT_ALIAS")
        try:
            metadata = os.lstat(probe)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            target = Path(os.readlink(probe))
            if not target.is_absolute():
                target = probe.parent / target
            target = Path(os.path.abspath(os.fspath(target)))
            if target == production or production in target.parents:
                raise PermissionError("OPENROUTER_V3_MOCK_FORBIDS_PRODUCTION_ROOT_ALIAS")


async def execute_openrouter_v3_mock_transport(
    *,
    protected_state_root: Path,
    response_handler: Callable[[httpx.Request], httpx.Response],
) -> dict[str, object]:
    """Provider-free MockTransport helper bound to a disjoint test-only root.

    This function is the ONLY caller-injected transport seam in the v3 lane.
    It refuses the production root and requires an isolated temporary root;
    production execution never consults it.
    """

    root_str = str(protected_state_root)
    _reject_v3_production_root_alias(Path(root_str))
    resolved = str(Path(root_str).resolve(strict=False))
    if not any(marker in resolved for marker in _V3_TEST_ROOT_MARKERS):
        raise PermissionError("OPENROUTER_V3_MOCK_REQUIRES_ISOLATED_TEST_ROOT")
    return {
        "status": "MOCK_SEAM_READY",
        "protected_root": resolved,
        "snapshot_sha256": OPENROUTER_V3_SNAPSHOT_SHA256,
    }


# ---------------------------------------------------------------------------
# Exact persisted v3 packet: canonical DEV-24 member plan, public request
# model, builder/loader, source binding, and create-only writer.
#
# The v1/v2 implementation is read as a PATTERN REFERENCE only — no import,
# alias, subclass, or fallback authority from either historical lane exists
# here.  Every digest is computed independently under the v3 contract.
# ---------------------------------------------------------------------------


def _canonical_repository_root(candidate: object | None = None) -> Path:
    """Reject any caller/cwd/path/root injection against the import-time root."""

    if candidate is None:
        return REPOSITORY_ROOT
    resolved = Path(os.path.abspath(os.fspath(candidate)))
    if resolved != REPOSITORY_ROOT:
        raise PermissionError("OPENROUTER_V3_REPOSITORY_ROOT_NOT_CANONICAL")
    return REPOSITORY_ROOT


def _evidence_inventory_sha256_v3(bundle: object) -> str:
    sources = bundle.sources  # type: ignore[attr-defined]
    return canonical_sha256(
        [
            {
                "evidence_id": source.evidence_id,
                "source_kind": source.source_kind,
                "source_sha256": source.source_sha256,
                "span_sha256": source.span_sha256,
            }
            for source in sources
        ]
    )


def openrouter_v3_user_message_content_v3(
    *,
    place_id: str,
    evidence: Sequence[Mapping[str, str]],
) -> str:
    """Canonical v3 user JSON with no v1/v2 authority or predecessor values."""

    from itda.contracts.phase5_openrouter_recovery_v3 import (
        OPENROUTER_V3_USER_INSTRUCTION_TEXT,
    )

    rows: list[dict[str, str]] = []
    for row in evidence:
        if set(row) != {"evidence_id", "source_kind", "text"}:
            raise ValueError("OPENROUTER_V3_EVIDENCE_SHAPE_INVALID")
        normalized = {key: str(row[key]) for key in ("evidence_id", "source_kind", "text")}
        for child in normalized.values():
            folded = child.lower()
            if any(marker in folded for marker in _V3_FORBIDDEN_CONTENT_MARKERS):
                raise ValueError("OPENROUTER_V3_EVIDENCE_FORBIDDEN_CONTENT")
        rows.append(normalized)
    return json.dumps(
        {
            "instruction": OPENROUTER_V3_USER_INSTRUCTION_TEXT,
            "place_id": place_id,
            "evidence": rows,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


_V3_FORBIDDEN_CONTENT_MARKERS = (
    "blind",
    "secret",
    "api_key",
    "apikey",
    "authorization:",
    "bearer ",
)


class OpenRouterMemberPlanV3:
    """Closed provider-free r3 plan used only for packet construction/verify.

    ``request_bodies`` maps each ordered place to its exact canonical request
    body bytes; nothing here touches a provider client or a secret.
    """

    __slots__ = (
        "authority_id",
        "snapshot_sha256",
        "predecessor_consumption",
        "members",
        "first_passes",
        "retry_policy",
        "exposure_policy",
        "request_manifest_sha256",
        "request_bodies",
        "prompt_sha256",
        "checkout_commit_sha256",
        "checkout_manifest_sha256",
        "source_commit_sha256",
    )

    def __init__(
        self,
        *,
        authority_id: str,
        snapshot_sha256: str,
        predecessor_consumption: object,
        members: tuple[dict[str, object], ...],
        first_passes: tuple[dict[str, object], ...],
        retry_policy: Mapping[str, object],
        exposure_policy: Mapping[str, object],
        request_manifest_sha256: str,
        request_bodies: dict[str, bytes],
        prompt_sha256: str,
        checkout_commit_sha256: str,
        checkout_manifest_sha256: str,
        source_commit_sha256: str,
    ) -> None:
        self.authority_id = authority_id
        self.snapshot_sha256 = snapshot_sha256
        self.predecessor_consumption = predecessor_consumption
        self.members = members
        self.first_passes = first_passes
        self.retry_policy = retry_policy
        self.exposure_policy = exposure_policy
        self.request_manifest_sha256 = request_manifest_sha256
        self.request_bodies = request_bodies
        self.prompt_sha256 = prompt_sha256
        self.checkout_commit_sha256 = checkout_commit_sha256
        self.checkout_manifest_sha256 = checkout_manifest_sha256
        self.source_commit_sha256 = source_commit_sha256

    @property
    def predecessor_consumption_sha256(self) -> str:
        return str(self.predecessor_consumption.consumption_sha256)  # type: ignore[attr-defined]


def build_openrouter_member_plan_v3(
    bundles: Sequence[object],
    *,
    repository_root: object | None = None,
) -> OpenRouterMemberPlanV3:
    """Build the exact 24-place ordered v3 member plan (provider-free).

    Bundles must be the canonical DEV-24 set in canonical sorted order; the
    request bodies are computed independently under the v3 contract — v2
    bodies/digests are never copied or consulted.
    """

    from itda.contracts.phase5_openrouter_recovery_v3 import (
        OPENROUTER_V3_PROMPT_SHA256,
        build_predecessor_projection_from_public_history,
        openrouter_v3_request_body_fields,
    )
    from itda.domain.demo_profile_eligibility import _CANONICAL_DEV_IDS

    root = _canonical_repository_root(repository_root)
    del root
    snapshot = load_snapshot_v3_for_plan()
    predecessor = build_predecessor_projection_from_public_history()
    expected_places = tuple(sorted(_CANONICAL_DEV_IDS))
    supplied = tuple(bundle.place_id for bundle in bundles)
    if supplied != expected_places or len(set(supplied)) != 24:
        raise ValueError("OPENROUTER_V3_SOURCE_INVENTORY_NOT_CANONICAL_DEV24")
    fields = openrouter_v3_request_body_fields()
    members: list[dict[str, object]] = []
    first_passes: list[dict[str, object]] = []
    request_bodies: dict[str, bytes] = {}
    for order, bundle in enumerate(bundles, start=1):
        evidence = [
            {
                "evidence_id": s.evidence_id,
                "source_kind": s.source_kind,
                "text": s.text,
            }
            for s in bundle.sources
        ]
        user_content = openrouter_v3_user_message_content_v3(
            place_id=bundle.place_id, evidence=evidence
        )
        payload: dict[str, object] = {
            "model": fields["model"],
            "messages": [
                {"role": "system", "content": _v3_prompt_text()},
                {"role": "user", "content": user_content},
            ],
        }
        for key, value in fields.items():
            if key != "model":
                payload[key] = value
        body = canonical_json_bytes(payload)
        body_digest = hashlib.sha256(body).hexdigest()
        preimage = {
            "schema_version": OPENROUTER_V3_MEMBER_REQUEST_SCHEMA_LOCAL,
            "authority_id": OPENROUTER_V3_RECOVERY_AUTHORITY_ID,
            "place_id": bundle.place_id,
            "split": "DEV",
            "first_pass_order": order,
            "source_bundle_sha256": bundle.source_bundle_sha256,
            "evidence_inventory_sha256": _evidence_inventory_sha256_v3(bundle),
            "request_body_sha256": body_digest,
        }
        request_sha256 = canonical_sha256(preimage)
        members.append({**preimage, "request_sha256": request_sha256})
        first_pass_unsigned = {
            "schema_version": OPENROUTER_V3_FIRST_PASS_SCHEMA_LOCAL,
            "authority_id": OPENROUTER_V3_RECOVERY_AUTHORITY_ID,
            "place_id": bundle.place_id,
            "order": order,
            "request_body_sha256": body_digest,
        }
        first_passes.append(
            {
                **first_pass_unsigned,
                "request_sha256": canonical_sha256(first_pass_unsigned),
            }
        )
        request_bodies[bundle.place_id] = body
    manifest = canonical_sha256(first_passes)
    source_commit = resolve_source_commit_for_packet()
    checkout_manifest = contracts_checkout_manifest_sha256_v3(source_commit)
    return OpenRouterMemberPlanV3(
        authority_id=OPENROUTER_V3_RECOVERY_AUTHORITY_ID,
        snapshot_sha256=str(snapshot["snapshot_sha256"]),
        predecessor_consumption=predecessor.model_dump(mode="json"),
        members=tuple(members),
        first_passes=tuple(first_passes),
        retry_policy=dict(contracts_build_retry_policy_v3()),
        exposure_policy=dict(contracts_build_exposure_policy_v3()),
        request_manifest_sha256=manifest,
        request_bodies=request_bodies,
        prompt_sha256=OPENROUTER_V3_PROMPT_SHA256,
        checkout_commit_sha256=source_commit,
        checkout_manifest_sha256=checkout_manifest,
        source_commit_sha256=source_commit,
    )


OPENROUTER_V3_MEMBER_REQUEST_SCHEMA_LOCAL = "itda.phase5-openrouter-member-request.v3"
OPENROUTER_V3_FIRST_PASS_SCHEMA_LOCAL = "itda.phase5-openrouter-first-pass.v3"
OPENROUTER_V3_PUBLIC_PACKET_SCHEMA_LOCAL = "itda.phase5-openrouter-recovery-request.v3"


def build_openrouter_plan_v3(
    bundles: Sequence[object] | None = None,
) -> OpenRouterMemberPlanV3:
    """The one production plan entry over the fixed canonical bundle order.

    Without an explicit bundle sequence the plan revalidates the tracked
    canonical public source authority — tests may pass synthetic provider-
    free bundles instead.
    """

    if bundles is None:
        return build_openrouter_member_plan_v3(bundles=_verified_source_bundles_v3())
    return build_openrouter_member_plan_v3(bundles=bundles)


def load_snapshot_v3_for_plan() -> dict[str, object]:
    from itda.contracts.phase5_openrouter_recovery_v3 import (
        load_openrouter_snapshot_v3,
    )

    return dict(load_openrouter_snapshot_v3().model_dump(mode="json"))


def _v3_prompt_text() -> str:
    from itda.contracts.phase5_openrouter_recovery_v3 import OPENROUTER_V3_PROMPT_TEXT

    return OPENROUTER_V3_PROMPT_TEXT


def contracts_checkout_manifest_sha256_v3(source_commit: str) -> str:
    from itda.contracts.phase5_openrouter_recovery_v3 import checkout_manifest_sha256_v3

    return checkout_manifest_sha256_v3(source_commit)


def contracts_build_retry_policy_v3() -> object:
    from itda.contracts.phase5_openrouter_recovery_v3 import (
        build_openrouter_retry_policy_v3,
    )

    return build_openrouter_retry_policy_v3()


def contracts_build_exposure_policy_v3() -> object:
    from itda.contracts.phase5_openrouter_recovery_v3 import (
        build_openrouter_exposure_policy_v3,
    )

    return build_openrouter_exposure_policy_v3()


def resolve_source_commit_for_packet() -> str:
    """Fixed import-root HEAD before a packet exists (sole-parent rule later)."""

    from itda.contracts.phase5_openrouter_recovery_v3 import (
        resolve_openrouter_v3_source_commit,
    )

    return resolve_openrouter_v3_source_commit()


def build_openrouter_public_request_v3(
    *, plan: OpenRouterMemberPlanV3
) -> dict[str, object]:
    """Build the exact non-authorizing r3/v3 public packet in memory."""

    from itda.contracts.phase5_fresh24 import (
        FRESH24_MEMBERSHIP_SHA256,
        FRESH24_SOURCE_AUTHORITY_SHA256,
        FRESH24_SOURCE_INSTALL_RECEIPT_SHA256,
        FRESH24_SOURCE_INVENTORY_SHA256,
    )
    from itda.contracts.phase5_openrouter_recovery_v3 import (
        OPENROUTER_V3_CONFIG_VERSION,
        OPENROUTER_V3_ENDPOINT,
        OPENROUTER_V3_MODEL,
        OPENROUTER_V3_PREPROCESSING_VERSION,
        OPENROUTER_V3_PROFILE_SCHEMA,
        OPENROUTER_V3_PROMPT_SHA256,
        OPENROUTER_V3_PROVIDER_LANE,
        OPENROUTER_V3_SNAPSHOT_RELATIVE,
        OPENROUTER_V3_USER_INSTRUCTION_SHA256,
        OpenRouterPublicRequestV3,
    )
    from itda.contracts.phase5_openrouter_recovery_v3_paths import (
        OPENROUTER_V3_PROTECTED_ROOT_RELATIVE,
        OPENROUTER_V3_PUBLIC_REQUEST_RELATIVE,
        OPENROUTER_V3_TERMINAL_RELATIVE,
    )
    from itda.contracts.phase5_recovery_policy import (
        ACTIVATION_SUITE_SHA256,
        CONTRAST_SUITE_SHA256,
    )

    if plan.authority_id != OPENROUTER_V3_RECOVERY_AUTHORITY_ID:
        raise PermissionError("OPENROUTER_V3_PLAN_AUTHORITY_INVALID")
    snapshot = load_snapshot_v3_for_plan()
    if str(snapshot["snapshot_sha256"]) != plan.snapshot_sha256:
        raise ValueError("OPENROUTER_V3_PLAN_SNAPSHOT_DRIFT")
    fields = {
        "schema_version": OPENROUTER_V3_PUBLIC_PACKET_SCHEMA_LOCAL,
        "authority_id": OPENROUTER_V3_RECOVERY_AUTHORITY_ID,
        "provider_lane": OPENROUTER_V3_PROVIDER_LANE,
        "endpoint": OPENROUTER_V3_ENDPOINT,
        "model": OPENROUTER_V3_MODEL,
        "snapshot_relative_path": OPENROUTER_V3_SNAPSHOT_RELATIVE,
        "snapshot_sha256": plan.snapshot_sha256,
        "snapshot_accessed_at": str(snapshot["accessed_at"]),
        "snapshot_provenance_urls": dict(snapshot["provenance_urls"]),
        "public_request_relative_path": OPENROUTER_V3_PUBLIC_REQUEST_RELATIVE,
        "protected_root_relative_path": OPENROUTER_V3_PROTECTED_ROOT_RELATIVE,
        "terminal_relative_path": OPENROUTER_V3_TERMINAL_RELATIVE,
        "prompt_version": "phase5-openrouter-profile-sentinel-json.v3",
        "prompt_sha256": OPENROUTER_V3_PROMPT_SHA256,
        "user_instruction_version": "phase5-openrouter-user-instruction.v3",
        "user_instruction_sha256": OPENROUTER_V3_USER_INSTRUCTION_SHA256,
        "profile_schema_version": OPENROUTER_V3_PROFILE_SCHEMA,
        "preprocessing_version": OPENROUTER_V3_PREPROCESSING_VERSION,
        "config_version": OPENROUTER_V3_CONFIG_VERSION,
        "source_inventory_sha256": FRESH24_SOURCE_INVENTORY_SHA256,
        "source_authority_sha256": FRESH24_SOURCE_AUTHORITY_SHA256,
        "source_install_receipt_sha256": FRESH24_SOURCE_INSTALL_RECEIPT_SHA256,
        "membership_sha256": FRESH24_MEMBERSHIP_SHA256,
        "retention_profile": (
            "public-canonical-dev24-tourism-evidence-completion-no-personal-data"
        ),
        "reasoning_effort": "high",
        "max_price": {"prompt": "0", "completion": "0"},
        "price_status": "EXACT_ZERO",
        "checkout_commit_sha256": plan.checkout_commit_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "first_pass_count": 24,
        "member_count": 24,
        "first_passes": [dict(row) for row in plan.first_passes],
        "request_manifest_sha256": plan.request_manifest_sha256,
        "retry_policy": dict(plan.retry_policy),
        "exposure_policy": dict(plan.exposure_policy),
        "activation_suite_sha256": ACTIVATION_SUITE_SHA256,
        "contrast_suite_sha256": CONTRAST_SUITE_SHA256,
        "predecessor_consumption": dict(plan.predecessor_consumption),
        "blind_access": False,
        "secret_read": False,
        "provider_client_constructed": False,
        "network_attempted": False,
        "lifecycle_mutated": False,
        "historical_member_import": False,
        "predecessor_grants_retry": False,
        "predecessor_grants_authority": False,
    }
    packet = OpenRouterPublicRequestV3.model_validate(
        {**fields, "request_artifact_sha256": canonical_sha256(fields)}
    )
    return packet.model_dump(mode="json")


OPENROUTER_V3_USER_INSTRUCTION_VERSION_LOCAL = "phase5-openrouter-user-instruction.v3"


def build_openloader_v3(raw: bytes) -> dict[str, object]:
    """Parse one canonical v3 packet payload rejecting drift recursively.

    Exact raw-byte SHA binding happens through the caller's file digest; this
    loader enforces canonical byte equality, recursive duplicate-key
    rejection, exact key set, zero nulls, and the semantic self digest.
    """

    from itda.contracts.phase5_openrouter_recovery_v3 import (
        OpenRouterPublicRequestV3,
        load_snapshot_v3_bytes,
    )

    payload = load_snapshot_v3_bytes(raw, label="PACKET")
    if canonical_json_bytes(payload) != raw:
        raise ValueError("OPENROUTER_V3_PACKET_NOT_CANONICAL")
    parsed = OpenRouterPublicRequestV3.model_validate(payload).model_dump(mode="json")
    unsigned = {k: v for k, v in parsed.items() if k != "request_artifact_sha256"}
    if not hmac.compare_digest(
        str(parsed["request_artifact_sha256"]), canonical_sha256(unsigned)
    ):
        raise ValueError("OPENROUTER_V3_PACKET_SELF_DIGEST_DRIFT")
    return parsed


def semantic_request_digest_v3(packet: Mapping[str, object]) -> str:
    """The canonical semantic digest of the packet's unsigned preimage."""

    unsigned = {
        key: value for key, value in packet.items() if key != "request_artifact_sha256"
    }
    return canonical_sha256(unsigned)


def bind_packet_to_source_v3(
    *,
    checkout_commit_sha256: str,
    checkout_manifest_sha256: str,
    request_manifest_sha256: str,
    packet_bytes: bytes | None = None,
    repository_root: object | None = None,
) -> bool:
    """Bind a packet to its exact source tree and Git-derived packet commit."""

    import subprocess as _subprocess

    root = _canonical_repository_root(repository_root)
    require_known_manifest(request_manifest_sha256, checkout_commit_sha256)
    if not isinstance(checkout_manifest_sha256, str) or _DIGEST.fullmatch(
        checkout_manifest_sha256
    ) is None:
        raise ValueError("OPENROUTER_V3_CHECKOUT_MANIFEST_INVALID")
    recomputed_manifest = _checkout_manifest_sha256_from_git_v3(
        root=root, source_commit=checkout_commit_sha256
    )
    if not hmac.compare_digest(checkout_manifest_sha256, recomputed_manifest):
        raise PermissionError("OPENROUTER_V3_CHECKOUT_MANIFEST_DRIFTED")

    current_head = resolve_openrouter_v3_source_commit_local(root)
    source_files = _openrouter_v3_source_authority_files()
    source_drift = _subprocess.run(
        ["git", "diff", "--quiet", checkout_commit_sha256, "--", *source_files],
        cwd=root,
        check=False,
        capture_output=True,
    )
    if source_drift.returncode != 0:
        raise PermissionError("OPENROUTER_V3_PACKET_SOURCE_DRIFTED")
    if checkout_commit_sha256 == current_head and packet_bytes is None:
        return True

    packet_commit = _derive_packet_commit_v3(root=root, current_head=current_head)
    require_sole_parent_consistency_v3(
        packet_commit=packet_commit,
        expected_source_commit=checkout_commit_sha256,
        repository_root=root,
    )
    post_packet_source_commits = _subprocess.run(
        [
            "git",
            "log",
            "--format=%H",
            f"{packet_commit}..{current_head}",
            "--",
            *source_files,
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    if post_packet_source_commits:
        raise PermissionError("OPENROUTER_V3_PACKET_SOURCE_CHANGED_AFTER_PACKET")
    if packet_bytes is not None:
        committed = _subprocess.run(
            [
                "git",
                "show",
                f"{packet_commit}:artifacts/public/phase5/openrouter-recovery-v3-request.json",
            ],
            cwd=root,
            check=True,
            capture_output=True,
        ).stdout
        if committed != packet_bytes:
            raise PermissionError("OPENROUTER_V3_PACKET_COMMITTED_BYTES_DRIFTED")
    return True


def _openrouter_v3_source_authority_files() -> tuple[str, ...]:
    from itda.contracts.phase5_openrouter_recovery_v3 import (
        OPENROUTER_V3_SOURCE_AUTHORITY_FILES,
    )

    return OPENROUTER_V3_SOURCE_AUTHORITY_FILES


def _checkout_manifest_sha256_from_git_v3(*, root: Path, source_commit: str) -> str:
    import subprocess as _subprocess

    from itda.contracts.phase5_openrouter_recovery_v3 import (
        OPENROUTER_V3_MANIFEST_EXCLUDED_PATHS,
    )

    if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        raise ValueError("OPENROUTER_V3_SOURCE_COMMIT_INVALID")
    completed = _subprocess.run(
        ["git", "ls-tree", "-r", "-z", "--full-tree", source_commit],
        cwd=root,
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise PermissionError("OPENROUTER_V3_SOURCE_COMMIT_NOT_FOUND")
    rows: list[dict[str, str]] = []
    for record in completed.stdout.split(b"\0"):
        if not record:
            continue
        metadata, raw_name = record.split(b"\t", 1)
        mode, kind, object_id = metadata.decode("ascii").split(" ")
        name = raw_name.decode("utf-8")
        if name not in OPENROUTER_V3_MANIFEST_EXCLUDED_PATHS:
            rows.append(
                {"path": name, "mode": mode, "type": kind, "object_id": object_id}
            )
    if not rows:
        raise ValueError("OPENROUTER_V3_CHECKOUT_MANIFEST_EMPTY")
    return canonical_sha256(rows)


def _derive_packet_commit_v3(*, root: Path, current_head: str) -> str:
    import subprocess as _subprocess

    completed = _subprocess.run(
        [
            "git",
            "log",
            "--format=%H",
            "--diff-filter=A",
            current_head,
            "--",
            "artifacts/public/phase5/openrouter-recovery-v3-request.json",
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    commits = tuple(row for row in completed.stdout.splitlines() if row)
    if len(commits) != 1 or re.fullmatch(r"[0-9a-f]{40}", commits[0]) is None:
        raise PermissionError("OPENROUTER_V3_PACKET_COMMIT_NOT_DERIVABLE")
    return commits[0]


def require_known_manifest(
    request_manifest_sha256: str, checkout_commit_sha256: str
) -> None:
    if not isinstance(request_manifest_sha256, str) or not _DIGEST.fullmatch(
        request_manifest_sha256
    ):
        raise ValueError("OPENROUTER_V3_REQUEST_MANIFEST_INVALID")
    if not isinstance(checkout_commit_sha256, str) or re.fullmatch(
        r"[0-9a-f]{40}", checkout_commit_sha256
    ) is None:
        raise ValueError("OPENROUTER_V3_CHECKOUT_COMMIT_INVALID")


def resolve_openrouter_v3_source_commit_local(root: Path) -> str:
    import subprocess as _subprocess

    completed = _subprocess.run(
        ["git", "rev-parse", "HEAD^{commit}"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    commit = completed.stdout.strip()
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ValueError("OPENROUTER_V3_SOURCE_COMMIT_INVALID")
    return commit


def require_sole_parent_consistency_v3(
    *,
    packet_commit: str,
    expected_source_commit: str,
    repository_root: object | None = None,
) -> str:
    """Derive the sole parent and changed paths directly from Git."""

    import subprocess as _subprocess

    root = _canonical_repository_root(repository_root)
    if re.fullmatch(r"[0-9a-f]{40}", packet_commit) is None:
        raise ValueError("OPENROUTER_V3_PACKET_COMMIT_INVALID")
    if re.fullmatch(r"[0-9a-f]{40}", expected_source_commit) is None:
        raise ValueError("OPENROUTER_V3_SOURCE_COMMIT_INVALID")
    parents = _subprocess.run(
        ["git", "rev-list", "--parents", "-n", "1", packet_commit],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip().split()
    if len(parents) != 2:
        raise PermissionError("OPENROUTER_V3_PACKET_COMMIT_PARENT_INVALID")
    parent = parents[1]
    if parent != expected_source_commit:
        raise PermissionError("OPENROUTER_V3_PACKET_SOURCE_PARENT_DRIFTED")
    changed = _subprocess.run(
        ["git", "diff", "--name-only", "-z", parent, packet_commit],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    paths = tuple(
        raw.decode("utf-8") for raw in changed.split(b"\0") if raw
    )
    if paths != (
        "artifacts/public/phase5/openrouter-recovery-v3-request.json",
    ):
        raise PermissionError("OPENROUTER_V3_PACKET_COMMIT_NOT_ISOLATED")
    return parent


def write_openrouter_public_request_v3(output: Path | None = None) -> dict[str, object]:
    """Create-only fixed-path packet writer; never invoked by tests.

    Only the exact production public packet coordinate is legal; synthetic
    output aliases are rejected before any filesystem access.  The write is
    create-only (no replacement/symlink), mode 0644, fsync on both the file
    descriptor and the containing directory.
    """

    from itda.contracts.phase5_openrouter_recovery_v3_paths import (
        OPENROUTER_V3_PUBLIC_REQUEST_PATH,
    )

    target = OPENROUTER_V3_PUBLIC_REQUEST_PATH if output is None else output
    if Path(os.path.abspath(os.fspath(target))) != OPENROUTER_V3_PUBLIC_REQUEST_PATH:
        raise PermissionError("OPENROUTER_V3_WRITER_PATH_NOT_FIXED")
    plan = build_openrouter_plan_v3(_verified_source_bundles_v3())
    payload = build_openrouter_public_request_v3(plan=plan)
    serialized = canonical_json_bytes(payload)
    if OPENROUTER_V3_PUBLIC_REQUEST_PATH.exists():
        if OPENROUTER_V3_PUBLIC_REQUEST_PATH.is_symlink():
            raise FileExistsError("OPENROUTER_V3_REQUEST_OUTPUT_SYMLINK_FORBIDDEN")
        if OPENROUTER_V3_PUBLIC_REQUEST_PATH.read_bytes() != serialized:
            raise FileExistsError("OPENROUTER_V3_REQUEST_OUTPUT_ALREADY_DIFFERS")
        return payload
    parent = OPENROUTER_V3_PUBLIC_REQUEST_PATH.parent
    parent.mkdir(parents=True, exist_ok=True)
    parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        descriptor = os.open(
            OPENROUTER_V3_PUBLIC_REQUEST_PATH.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o644,
            dir_fd=parent_fd,
        )
        try:
            written = 0
            while written < len(serialized):
                count = os.write(descriptor, serialized[written:])
                if count <= 0:
                    raise OSError("short packet write")
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    return payload


def _verified_source_bundles_v3() -> tuple[object, ...]:
    """Revalidate the tracked canonical four-file public source authority.

    Delegates to the shared Fresh24 fixed-source revalidation (pattern-level
    reuse of a TRACKED PUBLIC verification path, never a v1/v2 lane import).
    Synthetic test roots are impossible here: the fixed root is the module-
    derived production coordinate.
    """

    from itda.pipeline.phase5_fresh24 import verify_fixed_source_authority

    return verify_fixed_source_authority()


def verify_openrouter_v3_packet_full(packet_bytes: bytes) -> dict[str, object]:
    """Full closed verification of one candidate packet byte image.

    Canonical bytes, recursive duplicate keys, exact self/raw digests,
    semantic digest, exact key set, 24 ordered first passes, capability
    facts false, predecessor dual-fact binding, and source-parent
    consistency all verify here — used by the CLI preflight when present.
    """

    from itda.contracts.phase5_openrouter_recovery_v3 import (
        OPENROUTER_V3_FIRST_PASS_COUNT,
    )

    payload = build_openloader_v3(packet_bytes)
    if hashlib.sha256(packet_bytes).hexdigest() != hashlib.sha256(
        canonical_json_bytes(payload)
    ).hexdigest():
        raise ValueError("OPENROUTER_V3_PACKET_RAW_DIGEST_DRIFT")
    passes = payload.get("first_passes")
    if not isinstance(passes, list) or len(passes) != OPENROUTER_V3_FIRST_PASS_COUNT:
        raise ValueError("OPENROUTER_V3_PACKET_FIRST_PASSES_INVALID")
    orders = [row.get("order") for row in passes]
    if orders != list(range(1, len(passes) + 1)):
        raise ValueError("OPENROUTER_V3_PACKET_FIRST_PASS_ORDER_DRIFT")
    places = [str(row.get("place_id")) for row in passes]
    if places != sorted(places) or len(set(places)) != len(places):
        raise ValueError("OPENROUTER_V3_PACKET_PLACES_NOT_CANONICAL")
    for fact in ("blind_access", "secret_read", "provider_client_constructed"):
        if payload.get(fact) is not False:
            raise ValueError(f"OPENROUTER_V3_PACKET_CAPABILITY_FACT_INVALID:{fact}")
    if payload.get("network_attempted") is not False or payload.get(
        "lifecycle_mutated"
    ) is not False:
        raise ValueError("OPENROUTER_V3_PACKET_CAPABILITY_FACT_INVALID")
    consumption = payload.get("predecessor_consumption")
    if not isinstance(consumption, dict) or consumption.get(
        "v2_unconsumed"
    ) is not True or consumption.get("v2_consumed_before_reserve") is not False:
        raise ValueError("OPENROUTER_V3_PACKET_PREDECESSOR_FACTS_INVALID")
    bind_packet_to_source_v3(
        checkout_commit_sha256=str(payload.get("checkout_commit_sha256")),
        checkout_manifest_sha256=str(payload.get("checkout_manifest_sha256")),
        request_manifest_sha256=str(payload.get("request_manifest_sha256")),
        packet_bytes=packet_bytes,
    )
    return payload


__all__ = [
    "OpenRouterCapabilityErrorV3",
    "OpenRouterDurableAuthorityStateV3",
    "OpenRouterJournalMarker",
    "OpenRouterMemberPlanV3",
    "OpenRouterProtectedStateLayoutV3",
    "OpenRouterSchedulerV3",
    "bind_packet_to_source_v3",
    "build_openloader_v3",
    "build_openrouter_member_plan_v3",
    "build_openrouter_plan_v3",
    "build_openrouter_public_request_v3",
    "execute_openrouter_v3_mock_transport",
    "require_fixed_openrouter_v3_paths",
    "require_sole_parent_consistency_v3",
    "semantic_request_digest_v3",
    "verify_openrouter_v3_packet_full",
    "write_openrouter_public_request_v3",
]
