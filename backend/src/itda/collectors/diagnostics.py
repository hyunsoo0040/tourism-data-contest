"""Durable, secret-scanned diagnostics for explicit live provider collection."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final
from uuid import uuid4

from itda.collectors.base import credential_material_present

SCHEMA_VERSION: Final = "provider-collection-diagnostic-v1"
MAX_EVENT_BYTES: Final = 4_096
MAX_COMPLETED_OPERATIONS: Final = 30
_SAFE_PROVIDERS: Final = frozenset({"TOUR_API", "ODII", "TOURISM_PHOTO"})
_SAFE_OPERATIONS: Final = frozenset(
    {
        "searchKeyword2",
        "detailCommon2",
        "detailImage2",
        "areaBasedList2",
        "detailIntro2",
        "detailInfo2",
        "themeSearchList",
        "themeBasedList",
        "storyBasedList",
        "list",
        "search",
        "detail",
        "sync",
        "galleryList1",
        "gallerySearchList1",
        "galleryDetailList1",
        "gallerySyncDetailList1",
    }
)
_SAFE_CATEGORIES: Final = frozenset(
    {
        "collection",
        "credential",
        "filesystem",
        "http",
        "network",
        "provider_response",
        "success",
    }
)
_SAFE_OUTCOMES: Final = frozenset(
    {
        "collection_completed",
        "collection_failed",
        "credential_unavailable",
        "http_error",
        "response",
        "transport_error",
        "retryable_for_resume",
        "terminal_operator_action",
    }
)


class ProviderDiagnosticsError(RuntimeError):
    """Fail-closed diagnostics error with a constant, non-sensitive message."""

    def __init__(self) -> None:
        super().__init__("provider diagnostics unavailable")


@dataclass(frozen=True, slots=True)
class DiagnosticOperation:
    """Bounded identity for one logical provider operation."""

    operation_id: str
    candidate_place_id: str
    candidate_name: str
    provider: str
    operation: str
    plan_sha256: str | None = None


def _utc_timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _bounded_text(value: str, *, maximum: int, fallback: str) -> str:
    if (
        not value
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        return fallback
    return value


def _safe_token(value: str, *, maximum: int, fallback: str) -> str:
    bounded = _bounded_text(value, maximum=maximum, fallback=fallback)
    if bounded == fallback:
        return fallback
    if not all(
        character.isascii() and (character.isalnum() or character in "._:-")
        for character in bounded
    ):
        return fallback
    return bounded


def sanitize_upstream_result_code(value: object) -> str | None:
    """Return only a bounded ASCII result-code token."""

    if type(value) not in (str, int):
        return None
    rendered = str(value)
    sanitized = _safe_token(rendered, maximum=80, fallback="[redacted]")
    return sanitized


def sanitize_upstream_result_message(value: object) -> str | None:
    """Return a bounded human message or one fixed redaction marker."""

    if not isinstance(value, str) or not value:
        return None
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > 200:
        return "[redacted]"
    folded = normalized.casefold()
    if (
        "://" in normalized
        or "?" in normalized
        or "=" in normalized
        or "%" in normalized
        or any(
            fragment in folded
            for fragment in (
                "authorization",
                "servicekey",
                "api_key",
                "apikey",
                "secret",
                "token",
            )
        )
        or any(
            not (character.isalnum() or character.isspace() or character in ".,:;!?()[]_-'")
            for character in normalized
        )
    ):
        return "[redacted]"
    return normalized


def _ensure_private_directory(directory: Path) -> None:
    missing: list[Path] = []
    cursor = directory
    while True:
        try:
            metadata = cursor.lstat()
        except FileNotFoundError:
            if cursor == cursor.parent:
                raise ProviderDiagnosticsError from None
            missing.append(cursor)
            cursor = cursor.parent
            continue
        except OSError:
            raise ProviderDiagnosticsError from None
        if not stat.S_ISDIR(metadata.st_mode) or cursor.is_symlink():
            raise ProviderDiagnosticsError
        break

    for path in reversed(missing):
        try:
            path.mkdir(mode=0o700)
            path.chmod(0o700, follow_symlinks=False)
        except OSError:
            raise ProviderDiagnosticsError from None

    try:
        metadata = directory.lstat()
    except OSError:
        raise ProviderDiagnosticsError from None
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or directory.is_symlink()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ProviderDiagnosticsError


class ProviderDiagnostics:
    """Exclusive append-only JSONL writer with per-event durability."""

    def __init__(
        self,
        *,
        directory_fd: int,
        file_fd: int,
        file_name: str,
        run_id: str,
    ) -> None:
        self._directory_fd = directory_fd
        self._file_fd = file_fd
        self._file_name = file_name
        self._run_id = run_id
        self._sequence = 0
        self._operation_sequence = 0
        self._credentials: tuple[str, ...] | None = None
        self._completed_operations: list[dict[str, str]] = []
        self._closed = False
        self._broken = False

    @classmethod
    def ensure_directory(cls, directory: Path) -> None:
        """Create and validate the private directory without creating a log."""

        _ensure_private_directory(directory)

    @classmethod
    def create(cls, directory: Path) -> ProviderDiagnostics:
        """Create a unique private log before any credential or network access."""

        cls.ensure_directory(directory)
        directory_flags = os.O_RDONLY
        directory_flags |= getattr(os, "O_DIRECTORY", 0)
        directory_flags |= getattr(os, "O_NOFOLLOW", 0)
        directory_flags |= getattr(os, "O_CLOEXEC", 0)
        try:
            directory_fd = os.open(directory, directory_flags)
        except OSError:
            raise ProviderDiagnosticsError from None

        run_id = uuid4().hex
        file_name = f"provider-collection-{run_id}.jsonl"
        file_flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL
        file_flags |= getattr(os, "O_NOFOLLOW", 0)
        file_flags |= getattr(os, "O_CLOEXEC", 0)
        file_fd: int | None = None
        file_created = False
        try:
            file_fd = os.open(file_name, file_flags, 0o600, dir_fd=directory_fd)
            file_created = True
            os.fchmod(file_fd, 0o600)
            metadata = os.fstat(file_fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1
            ):
                raise ProviderDiagnosticsError
            os.fsync(directory_fd)
        except (OSError, ProviderDiagnosticsError):
            if file_fd is not None:
                with suppress(OSError):
                    os.close(file_fd)
            if file_created:
                with suppress(OSError):
                    os.unlink(file_name, dir_fd=directory_fd)
            with suppress(OSError):
                os.close(directory_fd)
            raise ProviderDiagnosticsError from None
        assert file_fd is not None
        return cls(
            directory_fd=directory_fd,
            file_fd=file_fd,
            file_name=file_name,
            run_id=run_id,
        )

    @property
    def file_name(self) -> str:
        return self._file_name

    def bind_credentials(self, *credentials: str) -> None:
        if (
            self._closed
            or self._broken
            or not 1 <= len(credentials) <= 3
            or any(not credential for credential in credentials)
        ):
            raise ProviderDiagnosticsError
        self._credentials = tuple(credentials)

    def operation(
        self,
        *,
        candidate_place_id: str,
        candidate_name: str,
        provider: str,
        operation: str,
        plan_sha256: str | None = None,
    ) -> DiagnosticOperation:
        if provider not in _SAFE_PROVIDERS or operation not in _SAFE_OPERATIONS:
            raise ProviderDiagnosticsError
        place_id = _safe_token(candidate_place_id, maximum=80, fallback="")
        name = _bounded_text(candidate_name, maximum=120, fallback="")
        if not place_id or not name:
            raise ProviderDiagnosticsError
        if plan_sha256 is not None and (
            len(plan_sha256) != 64
            or any(character not in "0123456789abcdef" for character in plan_sha256)
        ):
            raise ProviderDiagnosticsError
        self._operation_sequence += 1
        return DiagnosticOperation(
            operation_id=f"{self._run_id}:{self._operation_sequence}",
            candidate_place_id=place_id,
            candidate_name=name,
            provider=provider,
            operation=operation,
            plan_sha256=plan_sha256,
        )

    def run_started(self) -> None:
        self._write_event({"event": "run_started"})

    def request_attempt_started(
        self,
        operation: DiagnosticOperation,
        *,
        attempt: int,
        max_attempts: int,
        timeout_seconds: float,
        request_sha256: str | None = None,
    ) -> None:
        event: dict[str, object] = {
            "event": "request_attempt_started",
            **self._operation_fields(operation),
            "attempt_id": f"{operation.operation_id}:{attempt}",
            "attempt": attempt,
            "max_attempts": max_attempts,
            "timeout_seconds": timeout_seconds,
        }
        self._add_digest_fields(
            event,
            request_sha256=request_sha256,
            plan_sha256=operation.plan_sha256,
        )
        self._write_event(event)

    def request_attempt(
        self,
        operation: DiagnosticOperation,
        *,
        attempt: int,
        max_attempts: int,
        timeout_seconds: float,
        outcome: str,
        category: str,
        retryable: bool,
        terminal_failure: bool,
        http_status: int | None = None,
        exception_class: str | None = None,
        provider_result_code: object | None = None,
        provider_result_value: object | None = None,
        normalized_outcome: str | None = None,
        retry_disposition: str | None = None,
        raw_body_sha256: str | None = None,
        raw_body_retention: str | None = None,
        raw_body_file: str | None = None,
        safe_headers: dict[str, str] | None = None,
        elapsed_ms: int | None = None,
        request_sha256: str | None = None,
    ) -> None:
        event: dict[str, object] = {
            "event": "request_attempt",
            **self._operation_fields(operation),
            "attempt_id": f"{operation.operation_id}:{attempt}",
            "attempt": attempt,
            "max_attempts": max_attempts,
            "timeout_seconds": timeout_seconds,
            "outcome": self._safe_outcome(outcome),
            "category": self._safe_category(category),
            "retryable": bool(retryable),
            "terminal_failure": bool(terminal_failure),
        }
        if http_status is not None:
            if type(http_status) is not int or not 100 <= http_status <= 599:
                raise ProviderDiagnosticsError
            event["http_status"] = http_status
        if exception_class is not None:
            event["exception_class"] = _safe_token(
                exception_class,
                maximum=80,
                fallback="RequestError",
            )
        self._add_attempt_evidence(
            event,
            operation=operation,
            provider_result_code=provider_result_code,
            provider_result_value=provider_result_value,
            normalized_outcome=normalized_outcome,
            retry_disposition=retry_disposition,
            raw_body_sha256=raw_body_sha256,
            raw_body_retention=raw_body_retention,
            raw_body_file=raw_body_file,
            safe_headers=safe_headers,
            elapsed_ms=elapsed_ms,
            request_sha256=request_sha256,
        )
        self._write_event(event)

    def request_succeeded(
        self,
        operation: DiagnosticOperation,
        *,
        attempt: int,
        http_status: int,
        upstream_result_code: str | None,
        upstream_result_message: str | None,
        normalized_outcome: str | None = None,
        raw_body_sha256: str | None = None,
        raw_body_retention: str | None = None,
        raw_body_file: str | None = None,
        safe_headers: dict[str, str] | None = None,
        elapsed_ms: int | None = None,
        request_sha256: str | None = None,
    ) -> None:
        event: dict[str, object] = {
            "event": "request_succeeded",
            **self._operation_fields(operation),
            "attempt": attempt,
            "http_status": http_status,
            "outcome": "response",
            "category": "success",
        }
        if upstream_result_code is not None:
            event["upstream_result_code"] = upstream_result_code
        if upstream_result_message is not None:
            event["upstream_result_message"] = upstream_result_message
        self._add_attempt_evidence(
            event,
            operation=operation,
            provider_result_code=upstream_result_code,
            provider_result_value=upstream_result_message,
            normalized_outcome=normalized_outcome,
            retry_disposition="DO_NOT_RETRY",
            raw_body_sha256=raw_body_sha256,
            raw_body_retention=raw_body_retention,
            raw_body_file=raw_body_file,
            safe_headers=safe_headers,
            elapsed_ms=elapsed_ms,
            request_sha256=request_sha256,
        )
        self._write_event(event)

    def request_failed(
        self,
        operation: DiagnosticOperation,
        *,
        outcome: str,
        category: str,
        attempt: int,
        http_status: int | None = None,
        exception_class: str | None = None,
        normalized_outcome: str | None = None,
        retry_disposition: str | None = None,
        provider_result_code: object | None = None,
        provider_result_value: object | None = None,
    ) -> None:
        event: dict[str, object] = {
            "event": "request_failed",
            **self._operation_fields(operation),
            "attempt": attempt,
            "outcome": self._safe_outcome(outcome),
            "category": self._safe_category(category),
            "terminal_failure": True,
        }
        if http_status is not None:
            if type(http_status) is not int or not 100 <= http_status <= 599:
                raise ProviderDiagnosticsError
            event["http_status"] = http_status
        if exception_class is not None:
            event["exception_class"] = _safe_token(
                exception_class,
                maximum=80,
                fallback="RequestError",
            )
        self._add_attempt_evidence(
            event,
            operation=operation,
            provider_result_code=provider_result_code,
            provider_result_value=provider_result_value,
            normalized_outcome=normalized_outcome,
            retry_disposition=retry_disposition,
        )
        self._write_event(event)

    def retain_attempt_body(
        self,
        operation: DiagnosticOperation,
        *,
        attempt: int,
        raw_body: bytes,
        raw_body_sha256: str,
    ) -> str:
        """Persist exact attempt bytes privately before their diagnostic event."""

        if self._closed or self._broken or self._credentials is None:
            raise ProviderDiagnosticsError
        if not 1 <= attempt <= 5 or hashlib.sha256(raw_body).hexdigest() != raw_body_sha256:
            raise ProviderDiagnosticsError
        if any(
            credential_material_present(raw_body, credential)
            for credential in self._credentials
        ):
            raise ProviderDiagnosticsError
        identity = hashlib.sha256(
            f"{operation.operation_id}:{attempt}".encode("ascii")
        ).hexdigest()[:16]
        file_name = f"attempt-{identity}-{raw_body_sha256}.bin"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        file_fd: int | None = None
        created = False
        try:
            file_fd = os.open(file_name, flags, 0o600, dir_fd=self._directory_fd)
            created = True
            os.fchmod(file_fd, 0o600)
            metadata = os.fstat(file_fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1
            ):
                raise ProviderDiagnosticsError
            view = memoryview(raw_body)
            while view:
                written = os.write(file_fd, view)
                if written <= 0:
                    raise OSError
                view = view[written:]
            os.fsync(file_fd)
            os.fsync(self._directory_fd)
        except (OSError, ProviderDiagnosticsError):
            self._broken = True
            if file_fd is not None:
                with suppress(OSError):
                    os.close(file_fd)
            if created:
                with suppress(OSError):
                    os.unlink(file_name, dir_fd=self._directory_fd)
            raise ProviderDiagnosticsError from None
        assert file_fd is not None
        os.close(file_fd)
        return file_name

    def complete_operation(self, operation: DiagnosticOperation) -> None:
        if len(self._completed_operations) >= MAX_COMPLETED_OPERATIONS:
            raise ProviderDiagnosticsError
        completed = {
            "candidate_place_id": operation.candidate_place_id,
            "provider": operation.provider,
            "operation": operation.operation,
        }
        self._completed_operations.append(completed)
        self._write_event(
            {
                "event": "operation_completed",
                **self._operation_fields(operation),
                "completed_operation_count": len(self._completed_operations),
            }
        )

    def terminal_failure(
        self,
        *,
        outcome: str,
        category: str,
        http_status: int | None = None,
        exception_class: str | None = None,
    ) -> None:
        event: dict[str, object] = {
            "event": "terminal_failure",
            "outcome": self._safe_outcome(outcome),
            "category": self._safe_category(category),
            "terminal_failure": True,
            "completed_operation_count": len(self._completed_operations),
            "completed_operations": list(self._completed_operations),
        }
        if http_status is not None:
            if type(http_status) is not int or not 100 <= http_status <= 599:
                raise ProviderDiagnosticsError
            event["http_status"] = http_status
        if exception_class is not None:
            event["exception_class"] = _safe_token(
                exception_class,
                maximum=80,
                fallback="CollectionError",
            )
        self._write_event(event)

    def terminal_credential_failure(self) -> None:
        """Persist one fixed safe terminal event before any credential is available."""

        if (
            self._closed
            or self._broken
            or self._credentials is not None
            or self._sequence != 0
            or self._completed_operations
        ):
            raise ProviderDiagnosticsError
        self._write_event_payload(
            {
                "event": "terminal_failure",
                "outcome": "credential_unavailable",
                "category": "credential",
                "terminal_failure": True,
                "completed_operation_count": 0,
                "completed_operations": [],
            },
            credentials=(),
        )

    def terminal_success(self) -> None:
        self._write_event(
            {
                "event": "run_completed",
                "outcome": "collection_completed",
                "category": "success",
                "terminal_failure": False,
                "completed_operation_count": len(self._completed_operations),
                "completed_operations": list(self._completed_operations),
            }
        )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            os.close(self._file_fd)
        finally:
            os.close(self._directory_fd)

    @staticmethod
    def _operation_fields(operation: DiagnosticOperation) -> dict[str, str]:
        return {
            "operation_id": operation.operation_id,
            "candidate_place_id": operation.candidate_place_id,
            "candidate_name": operation.candidate_name,
            "provider": operation.provider,
            "operation": operation.operation,
        }

    @staticmethod
    def _safe_category(category: str) -> str:
        if category not in _SAFE_CATEGORIES:
            raise ProviderDiagnosticsError
        return category

    @staticmethod
    def _safe_outcome(outcome: str) -> str:
        if outcome not in _SAFE_OUTCOMES:
            raise ProviderDiagnosticsError
        return outcome

    @staticmethod
    def _safe_sha256(value: str) -> str:
        if len(value) != 64 or any(
            character not in "0123456789abcdef" for character in value
        ):
            raise ProviderDiagnosticsError
        return value

    @classmethod
    def _add_digest_fields(
        cls,
        event: dict[str, object],
        *,
        request_sha256: str | None,
        plan_sha256: str | None,
    ) -> None:
        if request_sha256 is not None:
            event["request_sha256"] = cls._safe_sha256(request_sha256)
        if plan_sha256 is not None:
            event["plan_sha256"] = cls._safe_sha256(plan_sha256)

    @classmethod
    def _add_attempt_evidence(
        cls,
        event: dict[str, object],
        *,
        operation: DiagnosticOperation,
        provider_result_code: object | None = None,
        provider_result_value: object | None = None,
        normalized_outcome: str | None = None,
        retry_disposition: str | None = None,
        raw_body_sha256: str | None = None,
        raw_body_retention: str | None = None,
        raw_body_file: str | None = None,
        safe_headers: dict[str, str] | None = None,
        elapsed_ms: int | None = None,
        request_sha256: str | None = None,
    ) -> None:
        code = sanitize_upstream_result_code(provider_result_code)
        value = sanitize_upstream_result_message(provider_result_value)
        if code is not None:
            event["provider_result_code"] = code
        if value is not None:
            event["provider_result_value"] = value
        if normalized_outcome is not None:
            event["normalized_outcome"] = _safe_token(
                normalized_outcome,
                maximum=80,
                fallback="[redacted]",
            )
        if retry_disposition is not None:
            if retry_disposition not in {
                "RETRY",
                "DO_NOT_RETRY",
                "RETRYABLE_FOR_RESUME",
            }:
                raise ProviderDiagnosticsError
            event["retry_disposition"] = retry_disposition
        if raw_body_sha256 is not None:
            event["raw_body_sha256"] = cls._safe_sha256(raw_body_sha256)
        if raw_body_retention is not None:
            if raw_body_retention not in {
                "IMMUTABLE_ATTEMPT_SNAPSHOT",
                "REDACTED_CREDENTIAL",
            }:
                raise ProviderDiagnosticsError
            event["raw_body_retention"] = raw_body_retention
        if raw_body_file is not None:
            rendered_file = _safe_token(
                raw_body_file,
                maximum=180,
                fallback="",
            )
            if not rendered_file:
                raise ProviderDiagnosticsError
            event["raw_body_file"] = rendered_file
        if safe_headers is not None:
            allowed_headers = {
                "content-type",
                "retry-after",
                "x-ratelimit-limit",
                "x-ratelimit-remaining",
            }
            if not set(safe_headers).issubset(allowed_headers):
                raise ProviderDiagnosticsError
            event["safe_headers"] = {
                key: _bounded_text(value, maximum=500, fallback="[redacted]")
                for key, value in sorted(safe_headers.items())
            }
        if elapsed_ms is not None:
            if type(elapsed_ms) is not int or not 0 <= elapsed_ms <= 86_400_000:
                raise ProviderDiagnosticsError
            event["elapsed_ms"] = elapsed_ms
        cls._add_digest_fields(
            event,
            request_sha256=request_sha256,
            plan_sha256=operation.plan_sha256,
        )

    def _write_event(self, event: dict[str, object]) -> None:
        if self._closed or self._broken or self._credentials is None:
            raise ProviderDiagnosticsError
        self._write_event_payload(event, credentials=self._credentials)

    def _write_event_payload(
        self,
        event: dict[str, object],
        *,
        credentials: tuple[str, ...],
    ) -> None:
        self._sequence += 1
        payload = {
            "schema_version": SCHEMA_VERSION,
            "run_id": self._run_id,
            "sequence": self._sequence,
            "occurred_at": _utc_timestamp(),
            **event,
        }
        try:
            line = (
                json.dumps(
                    payload,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                + b"\n"
            )
        except (TypeError, ValueError):
            self._broken = True
            raise ProviderDiagnosticsError from None
        if len(line) > MAX_EVENT_BYTES or any(
            credential_material_present(line, secret) for secret in credentials
        ):
            self._broken = True
            raise ProviderDiagnosticsError
        try:
            view = memoryview(line)
            while view:
                written = os.write(self._file_fd, view)
                if written <= 0:
                    raise OSError
                view = view[written:]
            os.fsync(self._file_fd)
        except OSError:
            self._broken = True
            raise ProviderDiagnosticsError from None


__all__ = [
    "DiagnosticOperation",
    "ProviderDiagnostics",
    "ProviderDiagnosticsError",
    "SCHEMA_VERSION",
    "sanitize_upstream_result_code",
    "sanitize_upstream_result_message",
]
