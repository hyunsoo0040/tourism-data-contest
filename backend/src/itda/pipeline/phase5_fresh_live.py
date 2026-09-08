"""Durable, one-use live runner for the separately approved fresh NVIDIA cohort."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from itda.cli.freeze_preview import _rename_noreplace_at, open_directory_chain_no_follow
from itda.contracts.demo_profile_materialization import (
    MAX_PROVIDER_RESPONSE_BYTES,
    NVIDIA_AUTHORITY_SHA256,
    DemoSourceBundle,
    NvidiaMinimaxProfileMaterializationConfig,
)
from itda.contracts.phase5_fresh_cohort import (
    FRESH_AUTHORITY_ID,
    FRESH_EXPOSURE_CAP_MICRO_USD,
    FRESH_MAX_HTTP_ATTEMPTS,
    FRESH_RESERVATION_MICRO_USD,
    FreshLedgerEntry,
    FreshNvidiaExposureLedger,
    FreshProtectedStateDescriptor,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.domain.demo_profile_eligibility import (
    evaluate_nvidia_profile_publication,
    evaluate_nvidia_publication_cohort,
)
from itda.pipeline.demo_profile_materialization import (
    _publish_private_files,
    _require_no_symlink_ancestors,
)
from itda.pipeline.phase5_fresh_cohort import (
    FRESH_CONFIG_SHA256,
    FRESH_PROFILE_SCHEMA_SHA256,
    FRESH_PROMPT_SHA256,
    FRESH_PROMPT_VERSION,
    FreshCohortPlan,
    FreshDurableAuthorityState,
)
from itda.providers.nvidia_minimax_profile import (
    NvidiaMinimaxProfileAdapter,
    NvidiaProfileAdapterResult,
)

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_LEDGER_BYTES = 2 * 1024 * 1024


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("short fresh evidence write")
        offset += written


def _publish_exact_file(path: Path, payload: bytes) -> None:
    """Atomically publish one fixed canonical file; exact retries are idempotent."""

    parent = open_directory_chain_no_follow(path.parent, create=True)
    staging_name = f".phase5-fresh-terminal-{uuid.uuid4().hex}"
    published = False
    try:
        descriptor = os.open(
            staging_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=parent,
        )
        try:
            os.fchmod(descriptor, 0o600)
            _write_all(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            _rename_noreplace_at(parent, staging_name, parent, path.name)
            published = True
            os.fsync(parent)
        except FileExistsError:
            existing = os.open(
                path.name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent,
            )
            try:
                metadata = os.fstat(existing)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_nlink != 1
                    or metadata.st_size != len(payload)
                ):
                    raise FileExistsError(
                        "fresh terminal already contains invalid bytes"
                    ) from None
                current = b""
                while len(current) < metadata.st_size:
                    chunk = os.read(existing, metadata.st_size - len(current))
                    if not chunk:
                        raise FileExistsError(
                            "fresh terminal already contains truncated bytes"
                        ) from None
                    current += chunk
                if current != payload:
                    raise FileExistsError(
                        "fresh terminal already contains different bytes"
                    ) from None
            finally:
                os.close(existing)
    finally:
        if not published:
            with suppress(FileNotFoundError):
                os.unlink(staging_name, dir_fd=parent)
        os.close(parent)


def _fallback_post_claim_terminal(
    *,
    plan: FreshCohortPlan,
    ledger: FreshNvidiaExposureLedger,
    approval_sha256: str,
    claim_sha256: str,
    terminal_output: Path,
    failure_reason: str,
) -> dict[str, object]:
    """Publish a minimal safe terminal if the restricted journal itself fails."""

    fields: dict[str, object] = {
        "schema_version": "itda.phase5-fresh-provider-terminal.v1",
        "authority_id": plan.authority_id,
        "public_request_sha256": plan.public_request.public_request_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "approval_sha256": approval_sha256,
        "claim_sha256": claim_sha256,
        "status": "FAILED_UNACTIVATED",
        "failure_reason": failure_reason,
        "profile_count": 0,
        "eligible_count": 0,
        "low_confidence_count": 0,
        "attempt_count": ledger.attempt_count,
        "committed_micro_usd": ledger.committed_micro_usd,
        "outstanding_micro_usd": ledger.outstanding_micro_usd,
        "cumulative_exposure_cap_micro_usd": FRESH_EXPOSURE_CAP_MICRO_USD,
        "ledger_head_sha256": ledger.head_sha256,
        "attempt_sha256": [],
        "generation_sha256": None,
        "active_member_count": 0,
        "two_preference_rank_change": False,
        "activation_capability": False,
        "network_attempted": ledger.committed_micro_usd > 0,
        "recorded_at": _utc_now(),
    }
    fields["terminal_sha256"] = canonical_sha256(fields)
    _publish_exact_file(terminal_output, canonical_json_bytes(fields))
    return fields


class FreshDurableRunJournal:
    """Fresh-authority journal with durable exposure transitions and raw evidence."""

    def __init__(
        self,
        *,
        plan: FreshCohortPlan,
        descriptor: FreshProtectedStateDescriptor,
        ledger: FreshNvidiaExposureLedger,
        approval_sha256: str,
    ) -> None:
        if plan.authority_id != FRESH_AUTHORITY_ID or descriptor.authority_id != plan.authority_id:
            raise PermissionError("FRESH_LIVE_AUTHORITY_MISMATCH")
        if not _DIGEST.fullmatch(approval_sha256):
            raise ValueError("fresh live approval digest is invalid")
        self._plan = plan
        self._descriptor = descriptor
        self._ledger = ledger
        self._approval_sha256 = approval_sha256
        self._journal_root = Path(descriptor.journal_target)
        self._raw_root = Path(descriptor.raw_evidence_target)
        self._ledger_path = Path(descriptor.ledger_target)
        if self._ledger_path.parent != Path(descriptor.state_root):
            raise PermissionError("FRESH_LEDGER_TARGET_MISMATCH")
        _require_no_symlink_ancestors(self._journal_root)
        _require_no_symlink_ancestors(self._raw_root)
        _require_no_symlink_ancestors(self._ledger_path.parent)

    @property
    def generation_root(self) -> Path:
        return Path(self._descriptor.state_root).parent / "generations"

    def acquire_run_lease(self) -> tuple[int, int]:
        """Acquire the process-lifetime lease shared by live and recovery paths."""

        state = open_directory_chain_no_follow(Path(self._descriptor.state_root))
        lock_descriptor = -1
        try:
            state_metadata = os.fstat(state)
            if (
                not stat.S_ISDIR(state_metadata.st_mode)
                or stat.S_IMODE(state_metadata.st_mode) != 0o700
            ):
                raise PermissionError("FRESH_PROTECTED_STATE_ROOT_NOT_PRIVATE")
            try:
                lock_descriptor = os.open(
                    "run.lock",
                    os.O_RDWR
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=state,
                )
                os.fchmod(lock_descriptor, 0o600)
                os.fsync(lock_descriptor)
                os.fsync(state)
            except FileExistsError:
                lock_descriptor = os.open(
                    "run.lock",
                    os.O_RDWR
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=state,
                )
            lock_metadata = os.fstat(lock_descriptor)
            if (
                not stat.S_ISREG(lock_metadata.st_mode)
                or stat.S_IMODE(lock_metadata.st_mode) != 0o600
                or lock_metadata.st_nlink != 1
                or lock_metadata.st_size != 0
            ):
                raise PermissionError("FRESH_LIVE_RUN_LOCK_INVALID")
            try:
                fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise PermissionError("FRESH_LIVE_RUN_ACTIVE") from error
            return state, lock_descriptor
        except BaseException:
            if lock_descriptor >= 0:
                os.close(lock_descriptor)
            os.close(state)
            raise

    @staticmethod
    def release_run_lease(lease: tuple[int, int]) -> None:
        state, lock_descriptor = lease
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        finally:
            os.close(lock_descriptor)
            os.close(state)

    def require_pristine(self) -> None:
        if (
            self._journal_root.exists()
            or self._raw_root.exists()
            or self._ledger_path.exists()
        ):
            raise PermissionError("FRESH_LIVE_AUTHORITY_ALREADY_CONSUMED")

    def record_live_start(self, *, claim_sha256: str) -> None:
        fields = {
            "schema_version": "itda.phase5-fresh-live-start.v1",
            "authority_id": self._plan.authority_id,
            "public_request_sha256": self._plan.public_request.public_request_sha256,
            "checkout_manifest_sha256": self._plan.checkout_manifest_sha256,
            "approval_sha256": self._approval_sha256,
            "claim_sha256": claim_sha256,
            "started_at": _utc_now(),
        }
        fields["live_start_sha256"] = canonical_sha256(fields)
        _publish_private_files(
            self._journal_root / "live-start",
            {"live-start.json": canonical_json_bytes(fields)},
            prefix=".phase5-fresh-live-start-",
            allow_existing=False,
        )

    def record_reservation(self, fields: Mapping[str, object]) -> None:
        """Persist the ledger RESERVE and reservation before lazy credential access."""

        self.sync_ledger()
        attempt_number = fields.get("attempt_number")
        request_sha256 = fields.get("request_sha256")
        if (
            type(attempt_number) is not int
            or not 1 <= attempt_number <= FRESH_MAX_HTTP_ATTEMPTS
            or not isinstance(request_sha256, str)
            or _DIGEST.fullmatch(request_sha256) is None
            or fields.get("authority_id") != self._plan.authority_id
            or fields.get("reservation_micro_usd") != FRESH_RESERVATION_MICRO_USD
        ):
            raise PermissionError("FRESH_RESERVATION_IDENTITY_MISMATCH")
        payload = {
            "schema_version": "itda.phase5-fresh-reservation-journal.v1",
            "authority_id": self._plan.authority_id,
            "approval_sha256": self._approval_sha256,
            **dict(fields),
            "reserved_at": _utc_now(),
        }
        payload["journal_sha256"] = canonical_sha256(payload)
        _publish_private_files(
            self._journal_root
            / "reservations"
            / f"{attempt_number:02d}-{request_sha256}",
            {"reservation.json": canonical_json_bytes(payload)},
            prefix=".phase5-fresh-reservation-",
            allow_existing=False,
        )

    def _open_state_root(self) -> int:
        descriptor = open_directory_chain_no_follow(self._ledger_path.parent)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            os.close(descriptor)
            raise PermissionError("FRESH_PROTECTED_STATE_ROOT_NOT_PRIVATE")
        return descriptor

    def _open_ledger_at(self, state_descriptor: int, *, create: bool) -> tuple[int, bool]:
        created = False
        if create:
            try:
                descriptor = os.open(
                    self._ledger_path.name,
                    os.O_RDWR
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=state_descriptor,
                )
                created = True
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
                os.fsync(state_descriptor)
            except FileExistsError:
                descriptor = os.open(
                    self._ledger_path.name,
                    os.O_RDWR
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=state_descriptor,
                )
        else:
            descriptor = os.open(
                self._ledger_path.name,
                os.O_RDWR
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=state_descriptor,
            )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size > _MAX_LEDGER_BYTES
        ):
            os.close(descriptor)
            raise PermissionError("FRESH_DURABLE_LEDGER_INVALID")
        return descriptor, created

    def _read_ledger_descriptor(self, descriptor: int) -> bytes:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size > _MAX_LEDGER_BYTES
        ):
            raise PermissionError("FRESH_DURABLE_LEDGER_INVALID")
        os.lseek(descriptor, 0, os.SEEK_SET)
        payload = b""
        while len(payload) < before.st_size:
            chunk = os.read(descriptor, before.st_size - len(payload))
            if not chunk:
                raise PermissionError("FRESH_DURABLE_LEDGER_TRUNCATED")
            payload += chunk
        after = os.fstat(descriptor)
        if (
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
            raise PermissionError("FRESH_DURABLE_LEDGER_CHANGED_DURING_READ")
        return payload

    def sync_ledger(self) -> None:
        entries = self._ledger.entries
        state_descriptor = self._open_state_root()
        try:
            descriptor, _created = self._open_ledger_at(state_descriptor, create=True)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                existing = self._read_ledger_descriptor(descriptor)
                durable = self._parse_ledger(existing)
                intended = tuple(self._entry_payload(entry) for entry in entries)
                if durable != intended[: len(durable)]:
                    raise PermissionError("FRESH_DURABLE_LEDGER_DRIFT")
                os.lseek(descriptor, 0, os.SEEK_END)
                for payload in intended[len(durable) :]:
                    _write_all(descriptor, canonical_json_bytes(payload) + b"\n")
                os.fsync(descriptor)
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
            os.fsync(state_descriptor)
        finally:
            os.close(state_descriptor)

    def reconcile_interrupted(
        self,
        *,
        terminal_output: Path,
        claim_sha256: str,
    ) -> dict[str, object]:
        """Terminalize a claimed restart without acquiring provider capability."""

        state_descriptor = self._open_state_root()
        try:
            descriptor, _created = self._open_ledger_at(state_descriptor, create=True)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                rows = list(self._parse_ledger(self._read_ledger_descriptor(descriptor)))
                outstanding: dict[int, dict[str, object]] = {}
                for row in rows:
                    reservation_id = row["reservation_id"]
                    if type(reservation_id) is not int:
                        raise PermissionError("FRESH_DURABLE_LEDGER_DRIFT")
                    if row["operation"] == "RESERVE":
                        outstanding[reservation_id] = row
                    else:
                        outstanding.pop(reservation_id, None)
                predecessor = str(rows[-1]["entry_sha256"]) if rows else "0" * 64
                os.lseek(descriptor, 0, os.SEEK_END)
                for reservation_id in sorted(outstanding):
                    sequence = len(rows) + 1
                    fields: dict[str, object] = {
                        "schema_version": "itda.phase5-fresh-ledger-entry.v1",
                        "authority_id": self._plan.authority_id,
                        "sequence": sequence,
                        "operation": "RECOVER_UNRESOLVED",
                        "reservation_id": reservation_id,
                        "amount_micro_usd": FRESH_RESERVATION_MICRO_USD,
                        "predecessor_sha256": predecessor,
                    }
                    fields["entry_sha256"] = canonical_sha256(
                        {
                            "authority_id": self._plan.authority_id,
                            "sequence": sequence,
                            "operation": "RECOVER_UNRESOLVED",
                            "reservation_id": reservation_id,
                            "amount_micro_usd": FRESH_RESERVATION_MICRO_USD,
                            "predecessor_sha256": predecessor,
                        }
                    )
                    _write_all(descriptor, canonical_json_bytes(fields) + b"\n")
                    rows.append(fields)
                    predecessor = str(fields["entry_sha256"])
                os.fsync(descriptor)
                os.fsync(state_descriptor)

                committed = sum(
                    FRESH_RESERVATION_MICRO_USD
                    for row in rows
                    if row["operation"] in {"COMMIT", "RECOVER_UNRESOLVED"}
                )
                attempts = sum(row["operation"] == "RESERVE" for row in rows)
                ledger_head_sha256 = (
                    str(rows[-1]["entry_sha256"]) if rows else "0" * 64
                )
                existing = self._load_existing_terminal(
                    terminal_output,
                    claim_sha256=claim_sha256,
                    attempt_count=attempts,
                    committed_micro_usd=committed,
                    ledger_head_sha256=ledger_head_sha256,
                )
                if existing is not None:
                    return existing
                return self._publish_reconciliation_terminal(
                    terminal_output=terminal_output,
                    claim_sha256=claim_sha256,
                    attempt_count=attempts,
                    committed_micro_usd=committed,
                    ledger_head_sha256=ledger_head_sha256,
                )
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
        finally:
            os.close(state_descriptor)

    def _read_terminal_file(self, path: Path) -> bytes:
        parent = open_directory_chain_no_follow(path.parent)
        try:
            descriptor = os.open(
                path.name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent,
            )
            try:
                before = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or stat.S_IMODE(before.st_mode) != 0o600
                    or before.st_nlink != 1
                    or not 0 < before.st_size <= 2 * 1024 * 1024
                ):
                    raise PermissionError("FRESH_PROVIDER_TERMINAL_INVALID")
                payload = b""
                while len(payload) < before.st_size:
                    chunk = os.read(descriptor, before.st_size - len(payload))
                    if not chunk:
                        raise PermissionError("FRESH_PROVIDER_TERMINAL_INVALID")
                    payload += chunk
                after = os.fstat(descriptor)
                if (
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
                    raise PermissionError("FRESH_PROVIDER_TERMINAL_INVALID")
                return payload
            finally:
                os.close(descriptor)
        finally:
            os.close(parent)

    def _load_existing_terminal(
        self,
        terminal_output: Path,
        *,
        claim_sha256: str,
        attempt_count: int,
        committed_micro_usd: int,
        ledger_head_sha256: str,
    ) -> dict[str, object] | None:
        private_terminal = self._journal_root / "terminal" / "terminal.json"
        try:
            private_payload = self._read_terminal_file(private_terminal)
        except FileNotFoundError:
            if os.path.lexists(terminal_output):
                raise PermissionError("FRESH_PROVIDER_TERMINAL_INVALID") from None
            return None
        try:
            public_payload = self._read_terminal_file(terminal_output)
        except FileNotFoundError:
            public_payload = None
        if public_payload is not None and public_payload != private_payload:
            raise PermissionError("FRESH_PROVIDER_TERMINAL_INVALID")
        try:
            value = json.loads(private_payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PermissionError("FRESH_PROVIDER_TERMINAL_INVALID") from error
        expected_keys = {
            "schema_version",
            "authority_id",
            "public_request_sha256",
            "checkout_manifest_sha256",
            "approval_sha256",
            "claim_sha256",
            "status",
            "failure_reason",
            "profile_count",
            "eligible_count",
            "low_confidence_count",
            "attempt_count",
            "committed_micro_usd",
            "outstanding_micro_usd",
            "cumulative_exposure_cap_micro_usd",
            "ledger_head_sha256",
            "attempt_sha256",
            "generation_sha256",
            "active_member_count",
            "two_preference_rank_change",
            "activation_capability",
            "network_attempted",
            "recorded_at",
            "terminal_sha256",
        }
        if (
            not isinstance(value, dict)
            or set(value) != expected_keys
            or canonical_json_bytes(value) != private_payload
            or value.get("schema_version")
            != "itda.phase5-fresh-provider-terminal.v1"
            or value.get("authority_id") != self._plan.authority_id
            or value.get("public_request_sha256")
            != self._plan.public_request.public_request_sha256
            or value.get("checkout_manifest_sha256")
            != self._plan.checkout_manifest_sha256
            or value.get("approval_sha256") != self._approval_sha256
            or value.get("claim_sha256") != claim_sha256
            or value.get("attempt_count") != attempt_count
            or value.get("committed_micro_usd") != committed_micro_usd
            or value.get("outstanding_micro_usd") != 0
            or value.get("cumulative_exposure_cap_micro_usd")
            != FRESH_EXPOSURE_CAP_MICRO_USD
            or value.get("ledger_head_sha256") != ledger_head_sha256
            or value.get("active_member_count") != 0
            or value.get("two_preference_rank_change") is not False
            or value.get("network_attempted") is not (committed_micro_usd > 0)
            or value.get("terminal_sha256")
            != canonical_sha256(
                {key: item for key, item in value.items() if key != "terminal_sha256"}
            )
        ):
            raise PermissionError("FRESH_PROVIDER_TERMINAL_INVALID")
        for count_name in ("profile_count", "eligible_count", "low_confidence_count"):
            count = value.get(count_name)
            if type(count) is not int or count < 0:
                raise PermissionError("FRESH_PROVIDER_TERMINAL_INVALID")
        attempt_sha256 = value.get("attempt_sha256")
        if (
            not isinstance(attempt_sha256, list)
            or len(attempt_sha256) > attempt_count
            or any(
                not isinstance(item, str) or _DIGEST.fullmatch(item) is None
                for item in attempt_sha256
            )
            or not isinstance(value.get("recorded_at"), str)
        ):
            raise PermissionError("FRESH_PROVIDER_TERMINAL_INVALID")
        status = value.get("status")
        if status == "COMPLETE_ELIGIBLE_UNACTIVATED":
            generation_sha256 = value.get("generation_sha256")
            if (
                value.get("failure_reason") is not None
                or value.get("activation_capability") is not True
                or value.get("profile_count") != 24
                or type(value.get("eligible_count")) is not int
                or int(value["eligible_count"]) < 5
                or not isinstance(generation_sha256, str)
                or _DIGEST.fullmatch(generation_sha256) is None
            ):
                raise PermissionError("FRESH_PROVIDER_TERMINAL_INVALID")
            receipt_payload = self._read_terminal_file(
                self.generation_root / generation_sha256 / "receipt.json"
            )
            try:
                receipt = json.loads(receipt_payload)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise PermissionError("FRESH_PROVIDER_TERMINAL_INVALID") from error
            if (
                not isinstance(receipt, dict)
                or canonical_json_bytes(receipt) != receipt_payload
                or receipt.get("generation_sha256") != generation_sha256
                or receipt.get("generation_sha256")
                != canonical_sha256(
                    {
                        key: item
                        for key, item in receipt.items()
                        if key != "generation_sha256"
                    }
                )
                or receipt.get("authority_id") != self._plan.authority_id
                or receipt.get("public_request_sha256")
                != self._plan.public_request.public_request_sha256
                or receipt.get("checkout_manifest_sha256")
                != self._plan.checkout_manifest_sha256
                or receipt.get("approval_sha256") != self._approval_sha256
                or receipt.get("profile_count") != value.get("profile_count")
                or receipt.get("attempt_count") != attempt_count
                or receipt.get("ledger_head_sha256") != ledger_head_sha256
                or receipt.get("status") != "COMPLETE_ELIGIBLE_UNACTIVATED"
            ):
                raise PermissionError("FRESH_PROVIDER_TERMINAL_INVALID")
        elif status == "FAILED_UNACTIVATED":
            if (
                not isinstance(value.get("failure_reason"), str)
                or not value.get("failure_reason")
                or value.get("activation_capability") is not False
                or value.get("generation_sha256") is not None
            ):
                raise PermissionError("FRESH_PROVIDER_TERMINAL_INVALID")
        else:
            raise PermissionError("FRESH_PROVIDER_TERMINAL_INVALID")
        if public_payload is None:
            _publish_exact_file(terminal_output, private_payload)
        return value

    def _publish_reconciliation_terminal(
        self,
        *,
        terminal_output: Path,
        claim_sha256: str,
        attempt_count: int,
        committed_micro_usd: int,
        ledger_head_sha256: str,
    ) -> dict[str, object]:
        fields: dict[str, object] = {
            "schema_version": "itda.phase5-fresh-provider-terminal.v1",
            "authority_id": self._plan.authority_id,
            "public_request_sha256": self._plan.public_request.public_request_sha256,
            "checkout_manifest_sha256": self._plan.checkout_manifest_sha256,
            "approval_sha256": self._approval_sha256,
            "claim_sha256": claim_sha256,
            "status": "FAILED_UNACTIVATED",
            "failure_reason": "FRESH_INTERRUPTED_UNRESOLVED_COMMITTED",
            "profile_count": 0,
            "eligible_count": 0,
            "low_confidence_count": 0,
            "attempt_count": attempt_count,
            "committed_micro_usd": committed_micro_usd,
            "outstanding_micro_usd": 0,
            "cumulative_exposure_cap_micro_usd": FRESH_EXPOSURE_CAP_MICRO_USD,
            "ledger_head_sha256": ledger_head_sha256,
            "attempt_sha256": [],
            "generation_sha256": None,
            "active_member_count": 0,
            "two_preference_rank_change": False,
            "activation_capability": False,
            "network_attempted": committed_micro_usd > 0,
            "recorded_at": _utc_now(),
        }
        fields["terminal_sha256"] = canonical_sha256(fields)
        serialized = canonical_json_bytes(fields)
        _publish_private_files(
            self._journal_root / "terminal",
            {"terminal.json": serialized},
            prefix=".phase5-fresh-recovery-terminal-",
            allow_existing=False,
        )
        _publish_exact_file(terminal_output, serialized)
        return fields

    def _parse_ledger(self, payload: bytes) -> tuple[dict[str, object], ...]:
        if not payload:
            return ()
        if not payload.endswith(b"\n"):
            raise PermissionError("FRESH_DURABLE_LEDGER_TRUNCATED")
        rows: list[dict[str, object]] = []
        predecessor = "0" * 64
        outstanding: set[int] = set()
        seen_reservations: set[int] = set()
        for expected_sequence, line in enumerate(payload.splitlines(), start=1):
            try:
                value = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise PermissionError("FRESH_DURABLE_LEDGER_INVALID") from error
            if not isinstance(value, dict) or canonical_json_bytes(value) != line:
                raise PermissionError("FRESH_DURABLE_LEDGER_NOT_CANONICAL")
            operation = value.get("operation")
            reservation_id = value.get("reservation_id")
            expected_sha = canonical_sha256(
                {
                    "authority_id": self._plan.authority_id,
                    "sequence": expected_sequence,
                    "operation": operation,
                    "reservation_id": reservation_id,
                    "amount_micro_usd": value.get("amount_micro_usd"),
                    "predecessor_sha256": predecessor,
                }
            )
            if (
                value.get("schema_version") != "itda.phase5-fresh-ledger-entry.v1"
                or value.get("authority_id") != self._plan.authority_id
                or value.get("sequence") != expected_sequence
                or value.get("predecessor_sha256") != predecessor
                or value.get("entry_sha256") != expected_sha
                or type(reservation_id) is not int
                or value.get("amount_micro_usd") != FRESH_RESERVATION_MICRO_USD
            ):
                raise PermissionError("FRESH_DURABLE_LEDGER_DRIFT")
            if operation == "RESERVE":
                if (
                    reservation_id in seen_reservations
                    or reservation_id != len(seen_reservations) + 1
                    or reservation_id > FRESH_MAX_HTTP_ATTEMPTS
                ):
                    raise PermissionError("FRESH_DURABLE_LEDGER_DRIFT")
                seen_reservations.add(reservation_id)
                outstanding.add(reservation_id)
            elif operation in {"RELEASE_BEFORE_SOCKET", "COMMIT", "RECOVER_UNRESOLVED"}:
                if reservation_id not in outstanding:
                    raise PermissionError("FRESH_DURABLE_LEDGER_DRIFT")
                outstanding.remove(reservation_id)
            else:
                raise PermissionError("FRESH_DURABLE_LEDGER_DRIFT")
            predecessor = expected_sha
            rows.append(value)
        return tuple(rows)

    def _entry_payload(self, entry: FreshLedgerEntry) -> dict[str, object]:
        return {
            "schema_version": "itda.phase5-fresh-ledger-entry.v1",
            "authority_id": self._plan.authority_id,
            **asdict(entry),
        }

    def record_attempt(
        self,
        result: NvidiaProfileAdapterResult,
        *,
        credential: str,
    ) -> None:
        self.sync_ledger()
        if not result.live_transport:
            raise PermissionError("FRESH_PRODUCTION_TRANSPORT_REQUIRED")
        request_sha256 = result.request_body_sha256
        if not isinstance(request_sha256, str) or _DIGEST.fullmatch(request_sha256) is None:
            raise PermissionError("FRESH_ATTEMPT_REQUEST_MISMATCH")
        raw = result.raw_response
        if raw is not None:
            raw = raw.replace(credential.encode("utf-8"), b"[REDACTED]")
            if credential.encode("utf-8") in raw:
                raise PermissionError("FRESH_RAW_REDACTION_FAILED")
        attempt = result.attempt.model_dump(mode="json")
        fields: dict[str, object] = {
            "schema_version": "itda.phase5-fresh-attempt-journal.v1",
            "authority_id": self._plan.authority_id,
            "approval_sha256": self._approval_sha256,
            "request_body_sha256": request_sha256,
            "attempt": attempt,
            "retry": result.retry,
            "raw_response_present": raw is not None,
            "raw_response_sha256": (
                hashlib.sha256(raw).hexdigest() if raw is not None else None
            ),
            "rate_limit_headers": dict(result.rate_limit_headers),
            "cooldown_seconds": result.cooldown_seconds,
            "cooldown_source": result.cooldown_source,
            "recorded_at": _utc_now(),
        }
        fields["journal_sha256"] = canonical_sha256(fields)
        metadata = canonical_json_bytes(fields)
        if credential.encode("utf-8") in metadata:
            raise PermissionError("FRESH_ATTEMPT_REDACTION_FAILED")
        attempt_name = f"{result.attempt.attempt_number:02d}-{result.attempt.attempt_sha256}"
        _publish_private_files(
            self._journal_root / "attempts" / attempt_name,
            {"attempt.json": metadata},
            prefix=".phase5-fresh-attempt-",
            allow_existing=False,
        )
        if raw is not None:
            if len(raw) > MAX_PROVIDER_RESPONSE_BYTES:
                raise PermissionError("FRESH_RAW_RESPONSE_TOO_LARGE")
            _publish_private_files(
                self._raw_root / attempt_name,
                {"raw-response.bin": raw},
                prefix=".phase5-fresh-raw-",
                allow_existing=False,
            )

    def publish_generation(
        self,
        *,
        profiles: Sequence[Mapping[str, object]],
        attempts: Sequence[NvidiaProfileAdapterResult],
    ) -> str:
        profile_rows = [dict(profile) for profile in profiles]
        attempt_rows = [result.attempt.model_dump(mode="json") for result in attempts]
        publication_decisions = [
            {
                "schema_version": "itda.phase5-fresh-publication-decision.v1",
                "place_id": profile.get("place_id"),
                "profile_sha256": profile.get("profile_sha256"),
                "recommendation_eligible": decision.recommendation_eligible,
                "reason": decision.reason,
            }
            for profile, decision in (
                (profile, evaluate_nvidia_profile_publication(profile))
                for profile in profile_rows
            )
        ]
        fields: dict[str, object] = {
            "schema_version": "itda.phase5-fresh-generation-receipt.v1",
            "authority_id": self._plan.authority_id,
            "public_request_sha256": self._plan.public_request.public_request_sha256,
            "checkout_manifest_sha256": self._plan.checkout_manifest_sha256,
            "approval_sha256": self._approval_sha256,
            "profile_count": len(profile_rows),
            "profile_sha256": [profile.get("profile_sha256") for profile in profile_rows],
            "attempt_count": len(attempt_rows),
            "attempt_sha256": [row.get("attempt_sha256") for row in attempt_rows],
            "publication_decisions_sha256": canonical_sha256(publication_decisions),
            "ledger_head_sha256": self._ledger.head_sha256,
            "status": "COMPLETE_ELIGIBLE_UNACTIVATED",
        }
        generation_sha256 = canonical_sha256(fields)
        receipt = {**fields, "generation_sha256": generation_sha256}
        _publish_private_files(
            self.generation_root / generation_sha256,
            {
                "profiles.json": canonical_json_bytes(profile_rows),
                "attempts.json": canonical_json_bytes(attempt_rows),
                "publication-decisions.json": canonical_json_bytes(
                    publication_decisions
                ),
                "receipt.json": canonical_json_bytes(receipt),
            },
            prefix=".phase5-fresh-generation-",
            immutable_conflict=True,
        )
        return generation_sha256

    def record_terminal(
        self,
        *,
        terminal_output: Path,
        claim_sha256: str,
        status: str,
        failure_reason: str | None,
        profiles: Sequence[Mapping[str, object]],
        attempts: Sequence[NvidiaProfileAdapterResult],
        generation_sha256: str | None,
    ) -> dict[str, object]:
        self.sync_ledger()
        decisions = [evaluate_nvidia_profile_publication(profile) for profile in profiles]
        fields: dict[str, object] = {
            "schema_version": "itda.phase5-fresh-provider-terminal.v1",
            "authority_id": self._plan.authority_id,
            "public_request_sha256": self._plan.public_request.public_request_sha256,
            "checkout_manifest_sha256": self._plan.checkout_manifest_sha256,
            "approval_sha256": self._approval_sha256,
            "claim_sha256": claim_sha256,
            "status": status,
            "failure_reason": failure_reason,
            "profile_count": len(profiles),
            "eligible_count": sum(
                decision.recommendation_eligible for decision in decisions
            ),
            "low_confidence_count": sum(
                decision.eligible and not decision.recommendation_eligible
                for decision in decisions
            ),
            "attempt_count": self._ledger.attempt_count,
            "committed_micro_usd": self._ledger.committed_micro_usd,
            "outstanding_micro_usd": self._ledger.outstanding_micro_usd,
            "cumulative_exposure_cap_micro_usd": FRESH_EXPOSURE_CAP_MICRO_USD,
            "ledger_head_sha256": self._ledger.head_sha256,
            "attempt_sha256": [result.attempt.attempt_sha256 for result in attempts],
            "generation_sha256": generation_sha256,
            "active_member_count": 0,
            "two_preference_rank_change": False,
            "activation_capability": status == "COMPLETE_ELIGIBLE_UNACTIVATED",
            "network_attempted": self._ledger.committed_micro_usd > 0,
            "recorded_at": _utc_now(),
        }
        fields["terminal_sha256"] = canonical_sha256(fields)
        serialized = canonical_json_bytes(fields)
        _publish_private_files(
            self._journal_root / "terminal",
            {"terminal.json": serialized},
            prefix=".phase5-fresh-terminal-",
            allow_existing=False,
        )
        _publish_exact_file(terminal_output, serialized)
        return fields


def _fresh_lineage(
    *,
    bundle: DemoSourceBundle,
    request_body: bytes,
) -> dict[str, object]:
    evidence_ids = tuple(source.evidence_id for source in bundle.sources)
    evidence_inventory_sha256 = canonical_sha256(
        [
            {
                "evidence_id": source.evidence_id,
                "source_kind": source.source_kind,
                "source_sha256": source.source_sha256,
                "span_sha256": source.span_sha256,
            }
            for source in bundle.sources
        ]
    )
    return {
        "prompt_version": FRESH_PROMPT_VERSION,
        "prompt_sha256": FRESH_PROMPT_SHA256,
        "profile_schema_sha256": FRESH_PROFILE_SCHEMA_SHA256,
        "config_sha256": FRESH_CONFIG_SHA256,
        "authority_sha256": NVIDIA_AUTHORITY_SHA256,
        "source_bundle_sha256": bundle.source_bundle_sha256,
        "evidence_inventory_sha256": evidence_inventory_sha256,
        "request_sha256": hashlib.sha256(request_body).hexdigest(),
        "evidence_ids": evidence_ids,
        "created_at": _utc_now(),
    }


async def execute_fresh_live_cohort(
    *,
    plan: FreshCohortPlan,
    authority: FreshDurableAuthorityState,
    descriptor: FreshProtectedStateDescriptor,
    terminal_output: Path,
    credential_reader: Callable[[], str],
) -> dict[str, object]:
    """Execute the exact approved DEV-24 plan through the sealed NVIDIA adapter."""

    status = authority.preflight()
    approval_sha256 = status.get("approval_sha256")
    if not isinstance(approval_sha256, str):
        raise PermissionError("FRESH_APPROVAL_REQUIRED")
    ledger = FreshNvidiaExposureLedger(authority_id=plan.authority_id)
    journal = FreshDurableRunJournal(
        plan=plan,
        descriptor=descriptor,
        ledger=ledger,
        approval_sha256=approval_sha256,
    )
    lease = journal.acquire_run_lease()
    try:
        return await _execute_fresh_live_cohort_locked(
            plan=plan,
            authority=authority,
            terminal_output=terminal_output,
            credential_reader=credential_reader,
            approval_sha256=approval_sha256,
            ledger=ledger,
            journal=journal,
        )
    finally:
        journal.release_run_lease(lease)


async def _execute_fresh_live_cohort_locked(
    *,
    plan: FreshCohortPlan,
    authority: FreshDurableAuthorityState,
    terminal_output: Path,
    credential_reader: Callable[[], str],
    approval_sha256: str,
    ledger: FreshNvidiaExposureLedger,
    journal: FreshDurableRunJournal,
) -> dict[str, object]:
    journal.require_pristine()
    claim = authority.claim_once()
    try:
        journal.record_live_start(claim_sha256=claim.claim_sha256)
    except Exception:
        return _fallback_post_claim_terminal(
            plan=plan,
            ledger=ledger,
            approval_sha256=approval_sha256,
            claim_sha256=claim.claim_sha256,
            terminal_output=terminal_output,
            failure_reason="FRESH_EVIDENCE_PERSISTENCE_FAILED",
        )

    last_credential = ""

    def guarded_credential_reader() -> str:
        nonlocal last_credential
        value = credential_reader()
        if not isinstance(value, str) or not value.strip():
            raise RuntimeError("FRESH_NVIDIA_SECRET_UNAVAILABLE")
        last_credential = value
        return value

    try:
        config = NvidiaMinimaxProfileMaterializationConfig.model_validate(
            {"authority_sha256": NVIDIA_AUTHORITY_SHA256}
        )
        adapter = NvidiaMinimaxProfileAdapter.for_fresh_authority(
            ledger=ledger,
            credential_reader=guarded_credential_reader,
            config=config,
        )
    except Exception:
        return _fallback_post_claim_terminal(
            plan=plan,
            ledger=ledger,
            approval_sha256=approval_sha256,
            claim_sha256=claim.claim_sha256,
            terminal_output=terminal_output,
            failure_reason="FRESH_LOCAL_CONFIGURATION_FAILED",
        )
    if not adapter.release_authorizing_transport:
        return journal.record_terminal(
            terminal_output=terminal_output,
            claim_sha256=claim.claim_sha256,
            status="FAILED_UNACTIVATED",
            failure_reason="FRESH_PRODUCTION_TRANSPORT_REQUIRED",
            profiles=(),
            attempts=(),
            generation_sha256=None,
        )

    bundles = {bundle.place_id: bundle for bundle in plan.source_bundles}
    requests = dict(plan.request_bodies)
    attempts: list[NvidiaProfileAdapterResult] = []
    terminal_by_place: dict[str, NvidiaProfileAdapterResult] = {}
    retryable: list[str] = []

    async def attempt(place_id: str) -> NvidiaProfileAdapterResult:
        try:
            result = await adapter.attempt(
                place_id=place_id,
                request_body=requests[place_id],
                lineage=_fresh_lineage(
                    bundle=bundles[place_id],
                    request_body=requests[place_id],
                ),
                reservation_sink=journal.record_reservation,
            )
        finally:
            journal.sync_ledger()
        journal.record_attempt(result, credential=last_credential)
        attempts.append(result)
        return result

    async def terminal_failure(reason: str) -> dict[str, object]:
        profiles = tuple(
            result.candidate.model_dump(mode="json")
            for result in terminal_by_place.values()
            if result.candidate is not None
        )
        return journal.record_terminal(
            terminal_output=terminal_output,
            claim_sha256=claim.claim_sha256,
            status="FAILED_UNACTIVATED",
            failure_reason=reason,
            profiles=profiles,
            attempts=attempts,
            generation_sha256=None,
        )

    try:
        for place_id, _request_body in plan.request_bodies:
            result = await attempt(place_id)
            if result.attempt.http_status == 429:
                return await terminal_failure("NVIDIA_RATE_LIMITED")
            if result.candidate is None:
                if result.retry:
                    retryable.append(place_id)
                    continue
                return await terminal_failure(
                    result.attempt.error_code or "NVIDIA_FRESH_TERMINAL_RESPONSE"
                )
            terminal_by_place[place_id] = result

        if len(retryable) > FRESH_MAX_HTTP_ATTEMPTS - len(plan.request_bodies):
            return await terminal_failure("NVIDIA_FRESH_EXPOSURE_BUDGET_EXHAUSTED")
        for place_id in retryable:
            result = await attempt(place_id)
            if result.candidate is None:
                return await terminal_failure(
                    "NVIDIA_RATE_LIMITED"
                    if result.attempt.http_status == 429
                    else result.attempt.error_code or "NVIDIA_FRESH_TERMINAL_RESPONSE"
                )
            terminal_by_place[place_id] = result
    except Exception as error:
        reason = (
            "NVIDIA_FRESH_EXPOSURE_BUDGET_EXHAUSTED"
            if str(error) == "NVIDIA_FRESH_EXPOSURE_BUDGET_EXHAUSTED"
            else "FRESH_LIVE_LOCAL_FAILURE"
        )
        try:
            return await terminal_failure(reason)
        except Exception:
            return _fallback_post_claim_terminal(
                plan=plan,
                ledger=ledger,
                approval_sha256=approval_sha256,
                claim_sha256=claim.claim_sha256,
                terminal_output=terminal_output,
                failure_reason="FRESH_EVIDENCE_PERSISTENCE_FAILED",
            )
    except BaseException:
        try:
            ledger.recover_unresolved()
            journal.sync_ledger()
            await terminal_failure("FRESH_LIVE_INTERRUPTED")
        except Exception:
            _fallback_post_claim_terminal(
                plan=plan,
                ledger=ledger,
                approval_sha256=approval_sha256,
                claim_sha256=claim.claim_sha256,
                terminal_output=terminal_output,
                failure_reason="FRESH_LIVE_INTERRUPTED",
            )
        raise

    try:
        profile_rows: list[Mapping[str, object]] = []
        for place_id, _request_body in plan.request_bodies:
            candidate = terminal_by_place[place_id].candidate
            if candidate is None:
                return await terminal_failure("NVIDIA_FRESH_TERMINAL_RESPONSE")
            profile_rows.append(candidate.model_dump(mode="json"))
        profiles = tuple(profile_rows)
        cohort = evaluate_nvidia_publication_cohort(profiles)
        if len(profiles) != 24 or not cohort.eligible or not cohort.recommendation_eligible:
            return await terminal_failure(cohort.reason)
        generation_sha256 = journal.publish_generation(profiles=profiles, attempts=attempts)
        return journal.record_terminal(
            terminal_output=terminal_output,
            claim_sha256=claim.claim_sha256,
            status="COMPLETE_ELIGIBLE_UNACTIVATED",
            failure_reason=None,
            profiles=profiles,
            attempts=attempts,
            generation_sha256=generation_sha256,
        )
    except Exception:
        return _fallback_post_claim_terminal(
            plan=plan,
            ledger=ledger,
            approval_sha256=approval_sha256,
            claim_sha256=claim.claim_sha256,
            terminal_output=terminal_output,
            failure_reason="FRESH_EVIDENCE_PERSISTENCE_FAILED",
        )


def reconcile_fresh_claimed_run(
    *,
    plan: FreshCohortPlan,
    authority: FreshDurableAuthorityState,
    descriptor: FreshProtectedStateDescriptor,
    terminal_output: Path,
) -> dict[str, object]:
    """Recover outstanding reservations and terminalize without provider capability."""

    status, claim = authority.claimed_preflight()
    approval_sha256 = status.get("approval_sha256")
    if not isinstance(approval_sha256, str):
        raise PermissionError("FRESH_APPROVAL_REQUIRED")
    journal = FreshDurableRunJournal(
        plan=plan,
        descriptor=descriptor,
        ledger=FreshNvidiaExposureLedger(authority_id=plan.authority_id),
        approval_sha256=approval_sha256,
    )
    lease = journal.acquire_run_lease()
    try:
        return journal.reconcile_interrupted(
            terminal_output=terminal_output,
            claim_sha256=claim.claim_sha256,
        )
    finally:
        journal.release_run_lease(lease)


__all__ = [
    "FreshDurableRunJournal",
    "execute_fresh_live_cohort",
    "reconcile_fresh_claimed_run",
]
