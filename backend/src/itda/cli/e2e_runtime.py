"""Fail-closed local PostgreSQL and FastAPI supervisor for Phase 01 browser UAT."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import FrameType
from typing import TYPE_CHECKING, Any, Protocol, cast

from itda.api.routes.photo import verify_photo_service_execute_surface

if TYPE_CHECKING:
    from itda.cli.freeze_labels import LabelFreezeReceipt
    from itda.contracts.profile_release_authority import ProfileReleaseAuthorityRequest

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
BACKEND_ROOT = REPOSITORY_ROOT / "backend"
WEB_ROOT = REPOSITORY_ROOT / "web"
COMPOSE_FILE = REPOSITORY_ROOT / "infra" / "compose.yaml"
ALEMBIC_INI = BACKEND_ROOT / "alembic.ini"

POSTGRES_IMAGE_DIGEST = "4f736ae292687621d4dbe0d499ffd024a36bd2ee7d8ca6f2ccd4c800f047b394"
POSTGRES_IMAGE = "docker.io/library/postgres:17.10-bookworm@sha256:" + POSTGRES_IMAGE_DIGEST
PLAYWRIGHT_VERSION = "1.61.1"
PLAYWRIGHT_CHROMIUM_REVISION = "1228"
API_HOST = "127.0.0.1"
API_PORT = 8000
API_READY_URL = f"http://{API_HOST}:{API_PORT}/v1/questionnaires/current"
FRONTEND_PROCESS_COMMAND = (
    "pnpm",
    "dev",
    "-H",
    API_HOST,
    "-p",
    "5173",
)
FRONTEND_SHUTDOWN_GRACE_SECONDS = 10.0
CLEANUP_BUDGET_SECONDS = 50.0
COMPOSE_DOWN_RESERVED_SECONDS = 25.0
PREREQUISITE_TIMEOUT_SECONDS = 300.0
DEFAULT_PREREQUISITE_TIMEOUT_SECONDS = 15.0
COMPOSE_UP_TIMEOUT_SECONDS = 300.0
COMPOSE_ACTIVE_PROBE_TIMEOUT_SECONDS = 15.0
POSTGRES_READY_TIMEOUT_SECONDS = 300.0
API_READY_TIMEOUT_SECONDS = 300.0
MIGRATION_TIMEOUT_SECONDS = 300.0
PLAYWRIGHT_STARTUP_TIMEOUT_SECONDS = 300.0
LIFECYCLE_TEARDOWN_MARGIN_SECONDS = 60.0
DATABASE_CONNECT_TIMEOUT_SECONDS = 3
DATABASE_STATEMENT_TIMEOUT_MS = 5_000
DATABASE_LOCK_TIMEOUT_MS = 3_000
STARTUP_POLL_SECONDS = 0.25
LIFECYCLE_INTENTIONAL_FAILURE_MARKER = "ITDA_E2E_INTENTIONAL_FAILURE_REACHED"
MIGRATION_CHILD_WORK_MARKER = "ITDA_E2E_ALEMBIC_WORK_ACTIVE"
PLAYWRIGHT_WEB_SERVER_NAMES = ("WebServer",)
LIFECYCLE_INTERRUPT_SENTINELS: dict[str | None, str] = {
    "compose-readiness": "ITDA_E2E_COMPOSE_RESOURCE_ACTIVE",
    "migration": "ITDA_E2E_MIGRATION_WORK_ACTIVE",
    None: "ITDA_E2E_READY_FOR_INTERRUPTION",
}
_ANSI_ESCAPE_SEQUENCE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
DATABASE_SESSION_OPTIONS = (
    f"-c statement_timeout={DATABASE_STATEMENT_TIMEOUT_MS} "
    f"-c lock_timeout={DATABASE_LOCK_TIMEOUT_MS}"
)
PHASE3_CAPABILITIES = (
    "evaluator_a",
    "evaluator_b",
    "evaluator_c",
    "adjudicator",
    "model_runner",
    "builder",
    "approver",
)
PROFILE_RELEASE_BUILDER_ACTOR_ID = "phase3-builder"
PROFILE_RELEASE_WRITE_AUTHORITY_ROLE = "itda_profile_release_write_authority"
PROFILE_RELEASE_AUTHORITY_SERVICE_ROLE = "itda_profile_release_authority_service"
PHOTO_WRITE_AUTHORITY_ROLE = "itda_photo_write_authority"
PHOTO_AUTHORITY_SERVICE_ROLE = "itda_photo_service"
PROFILE_SESSION_OWNER_ROLE = "itda_current_profile_session_owner"
PROFILE_SESSION_SERVICE_ROLE = "itda_current_profile_session_service"
DAILY_GLM_WRITE_AUTHORITY_ROLE = "itda_daily_glm_refresh_write_authority"
DAILY_GLM_SERVICE_ROLE = "itda_daily_glm_refresh_service"
PROFILE_SESSION_CURRENT_KID = "current"
PROFILE_SESSION_PREVIOUS_KID = "previous"
PROFILE_SESSION_CANONICAL_ORIGIN = "http://127.0.0.1:5173"
LABEL_FREEZE_OUTPUT_NAME = "label-freeze-receipt.json"
RELEASE_AUTHORITY_DIRECTORY_NAME = "release-authority"
RELEASE_AUTHORITY_FILES = {
    "label_freeze": "label-freeze-receipt.json",
    "candidate_manifest": "profile-release-candidates.json",
    "reviewed_manifest": "profile-release-reviewed.json",
    "rights_manifest": "profile-release-rights.json",
    "source_manifest": "profile-release-sources.json",
    "evidence_candidates": "evidence-candidates.json",
    "build_input": "profile-release-build-input.json",
}

_REQUIRED_ENVIRONMENT = {
    "ITDA_NO_NETWORK": "1",
    "MISE_OFFLINE": "1",
    "MISE_NOT_FOUND_AUTO_INSTALL": "0",
    "UV_OFFLINE": "1",
}
_PINNED_TOOLS = {
    "python": "3.13.14",
    "uv": "0.11.28",
    "node": "24.18.0",
    "pnpm": "11.15.1",
}
PINNED_TOOL_PREFLIGHT_PROBES = ("mise-where", "mise-which", "version")
DOCKER_PREFLIGHT_PROBES = ("context", "image")
LONG_PREFLIGHT_PROBES = ("uv-environment", "playwright-bundle")
PINNED_TOOL_PREFLIGHT_PROBE_COUNT = len(_PINNED_TOOLS) * len(PINNED_TOOL_PREFLIGHT_PROBES)
DOCKER_PREFLIGHT_PROBE_COUNT = len(DOCKER_PREFLIGHT_PROBES)
LONG_PREFLIGHT_PROBE_COUNT = len(LONG_PREFLIGHT_PROBES)
PREFLIGHT_SEQUENTIAL_BUDGETS = (
    DEFAULT_PREREQUISITE_TIMEOUT_SECONDS
    * (PINNED_TOOL_PREFLIGHT_PROBE_COUNT + DOCKER_PREFLIGHT_PROBE_COUNT),
    PREREQUISITE_TIMEOUT_SECONDS * LONG_PREFLIGHT_PROBE_COUNT,
)
PREFLIGHT_TIMEOUT_SECONDS = sum(PREFLIGHT_SEQUENTIAL_BUDGETS)
BACKEND_SEQUENTIAL_STARTUP_BUDGETS = (
    COMPOSE_UP_TIMEOUT_SECONDS,
    POSTGRES_READY_TIMEOUT_SECONDS,
    MIGRATION_TIMEOUT_SECONDS,
    API_READY_TIMEOUT_SECONDS,
)
BACKEND_PLAYWRIGHT_READINESS_TIMEOUT_SECONDS = (
    PREFLIGHT_TIMEOUT_SECONDS
    + sum(BACKEND_SEQUENTIAL_STARTUP_BUDGETS)
    + LIFECYCLE_TEARDOWN_MARGIN_SECONDS
)
LIFECYCLE_SEQUENTIAL_STARTUP_BUDGETS = (
    *PREFLIGHT_SEQUENTIAL_BUDGETS,
    *BACKEND_SEQUENTIAL_STARTUP_BUDGETS,
    PLAYWRIGHT_STARTUP_TIMEOUT_SECONDS,
)
LIFECYCLE_MODE_TIMEOUT_SECONDS = (
    sum(LIFECYCLE_SEQUENTIAL_STARTUP_BUDGETS) + LIFECYCLE_TEARDOWN_MARGIN_SECONDS
)
_SECRET_MARKERS = (
    "API_KEY",
    "AUTH",
    "CAPABILITY",
    "CREDENTIAL",
    "PASSWORD",
    "PRIVATE_KEY",
    "SECRET",
    "TOKEN",
)
_SAFE_EXACT_ENVIRONMENT = {
    "CI",
    "LANG",
    "PATH",
    "PLAYWRIGHT_BROWSERS_PATH",
    "PYTHONPATH",
    "SSL_CERT_FILE",
    "TERM",
    "TMPDIR",
    "TZ",
    "VIRTUAL_ENV",
}
_SAFE_PREFIXES = ("ITDA_E2E_", "LC_", "MISE_", "UV_")

PLAYWRIGHT_BUNDLE_PROBE = r"""
const fs = require("fs");
const path = require("path");
const testPackagePath = require.resolve("@playwright/test/package.json", {
  paths: [process.cwd()],
});
const corePackagePath = require.resolve("playwright-core/package.json", {
  paths: [path.dirname(testPackagePath)],
});
const coreRoot = path.dirname(corePackagePath);
const testPackage = require(testPackagePath);
const corePackage = require(corePackagePath);
const metadata = require(path.join(coreRoot, "browsers.json"));
const registry = require(path.join(coreRoot, "lib/coreBundle.js")).registry.registry;
const names = ["chromium", "chromium-headless-shell"];
const browsers = names.map((name) => {
  const entry = metadata.browsers.find((candidate) => candidate.name === name);
  const executable = registry.findExecutable(name);
  return {
    name,
    revision: entry && entry.revision,
    executablePath: executable && executable.executablePath(),
  };
});
process.stdout.write(JSON.stringify({
  testVersion: testPackage.version,
  coreVersion: corePackage.version,
  browsers,
}));
""".strip()


class PreflightError(RuntimeError):
    """A prerequisite failed before any mutable runtime resource was allocated."""


class StartupCancelled(RuntimeError):
    """Startup was interrupted and must unwind immediately."""


CommandRunner = Callable[
    [Sequence[str]],
    subprocess.CompletedProcess[str],
]


@dataclass(frozen=True, slots=True)
class PreflightReport:
    """Verified immutable local artifacts needed by the E2E runtime."""

    chromium_revision: str
    chromium_executable: Path
    chromium_headless_shell_executable: Path


@dataclass(slots=True)
class RuntimeResources:
    """Generated per-run identities and connection material."""

    suffix: str
    project_name: str
    database_name: str
    admin_name: str
    runtime_name: str
    port: int
    phase3_role_names: dict[str, str] = field(repr=False)
    phase3_capabilities: dict[str, str] = field(repr=False)
    phase3_passwords: dict[str, str] = field(repr=False)
    phase3_dsns: dict[str, str] = field(repr=False)
    admin_password: str = field(repr=False)
    runtime_password: str = field(repr=False)
    profile_release_authority_password: str = field(repr=False)
    photo_service_password: str = field(repr=False)
    profile_session_service_password: str = field(repr=False)
    daily_glm_service_password: str = field(repr=False)
    profile_session_current_key: str = field(repr=False)
    profile_session_previous_key: str = field(repr=False)
    compose_environment: dict[str, str] = field(repr=False)
    admin_dsn: str = field(repr=False)
    admin_postgres_dsn: str = field(repr=False)
    runtime_dsn: str = field(repr=False)
    profile_release_authority_dsn: str = field(repr=False)
    label_freeze_directory: Path = field(repr=False)
    label_freeze_output: Path = field(repr=False)
    label_freeze_directory_identity: tuple[int, int] = field(repr=False)
    photo_service_dsn: str = field(repr=False)
    profile_session_service_dsn: str = field(repr=False)
    photo_quarantine_directory: Path = field(repr=False)
    photo_quarantine_directory_identity: tuple[int, int] = field(repr=False)
    release_authority_directory: Path | None = field(default=None, repr=False)
    release_authority_directory_identity: tuple[int, int] | None = field(default=None, repr=False)
    release_authority_environment: dict[str, str] = field(default_factory=dict, repr=False)
    release_reviewed_records: tuple[dict[str, object], ...] = field(default=(), repr=False)
    release_build_authority_resolution: object | None = field(default=None, repr=False)

    @property
    def secrets(self) -> tuple[str, ...]:
        authority_paths = tuple(
            value
            for key, value in self.release_authority_environment.items()
            if key.endswith("MANIFEST") or key.endswith("BUILD_INPUT")
        )
        return (
            self.admin_password,
            self.runtime_password,
            self.profile_release_authority_password,
            self.photo_service_password,
            self.profile_session_service_password,
            self.daily_glm_service_password,
            self.profile_session_current_key,
            self.profile_session_previous_key,
            *self.phase3_capabilities.values(),
            *self.phase3_passwords.values(),
            self.admin_dsn,
            self.admin_postgres_dsn,
            self.runtime_dsn,
            self.profile_release_authority_dsn,
            self.photo_service_dsn,
            self.profile_session_service_dsn,
            *self.phase3_dsns.values(),
            str(self.label_freeze_directory),
            str(self.label_freeze_output),
            *(
                (str(self.release_authority_directory),)
                if self.release_authority_directory is not None
                else ()
            ),
            *authority_paths,
        )


@dataclass(frozen=True, slots=True)
class ReleaseAuthorityHandoff:
    """Private post-freeze authority graph plus a hash-only public receipt."""

    freeze_receipt_sha256: str
    candidate_freeze_receipt_sha256: str
    authority_directory: Path = field(repr=False)
    candidate_manifest_path: Path = field(repr=False)
    candidate_manifest_sha256: str
    server_environment: dict[str, str] = field(repr=False)
    public_receipt: dict[str, str]
    reviewed_records: tuple[dict[str, object], ...] = field(repr=False)


class RuntimeLifecycle(Protocol):
    def allocate(self) -> object: ...

    def compose_up(self, resources: object) -> None: ...

    def migrate(self, resources: object) -> None: ...

    def verify_runtime_role(self, resources: object) -> None: ...

    def start_api(self, resources: object) -> object: ...

    def wait_ready(self, resources: object, api_process: object) -> None: ...

    def wait_until_stopped(
        self, resources: object, api_process: object, stop_requested: object
    ) -> object | None: ...

    def stop_api(self, api_process: object) -> None: ...

    def cleanup_private_output(self, resources: object) -> None: ...

    def drop_database_and_role(self, resources: object) -> None: ...

    def compose_down(self, resources: object) -> None: ...


def _default_runner(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        cwd=cwd,
        env=dict(environment),
        capture_output=True,
        check=False,
        text=True,
        timeout=timeout,
    )


def _safe_environment(environment: Mapping[str, str]) -> dict[str, str]:
    safe: dict[str, str] = {}
    for key, value in environment.items():
        upper_key = key.upper()
        if any(marker in upper_key for marker in _SECRET_MARKERS):
            continue
        if (
            key in _SAFE_EXACT_ENVIRONMENT
            or key in _REQUIRED_ENVIRONMENT
            or key.startswith(_SAFE_PREFIXES)
        ):
            safe[key] = value
    return safe


def redact_diagnostic(message: str, secret_values: Sequence[str]) -> str:
    """Replace every known non-empty secret with a stable marker."""

    redacted = message
    for secret_value in sorted({value for value in secret_values if value}, key=len, reverse=True):
        redacted = redacted.replace(secret_value, "<redacted>")
    return redacted


def _private_runtime_directory(prefix: str) -> tuple[Path, tuple[int, int]]:
    directory = Path(tempfile.mkdtemp(prefix=prefix))
    try:
        os.chmod(directory, 0o700)
        details = os.lstat(directory)
        if not stat.S_ISDIR(details.st_mode) or stat.S_IMODE(details.st_mode) != 0o700:
            raise RuntimeError("private runtime directory allocation failed")
        return directory, (details.st_dev, details.st_ino)
    except BaseException:
        with suppress(OSError):
            os.rmdir(directory)
        raise


def _private_label_freeze_directory() -> tuple[Path, tuple[int, int]]:
    return _private_runtime_directory("itda-phase3-freeze-")


def _cleanup_private_photo_quarantine_directory(
    directory: Path,
    expected_identity: tuple[int, int],
) -> None:
    descriptor = _open_private_label_freeze_directory(
        directory,
        expected_identity,
        allow_missing=True,
    )
    if descriptor is None:
        return
    try:
        os.rmdir(directory)
    except OSError as error:
        raise RuntimeError("photo quarantine runtime residue detected") from error
    finally:
        os.close(descriptor)


def _validate_label_freeze_output(resources: RuntimeResources) -> None:
    expected_output = resources.label_freeze_directory / LABEL_FREEZE_OUTPUT_NAME
    if resources.label_freeze_output != expected_output:
        raise RuntimeError("private label freeze output validation failed")
    parent_descriptor = _open_private_label_freeze_directory(
        resources.label_freeze_directory,
        resources.label_freeze_directory_identity,
        allow_missing=False,
    )
    assert parent_descriptor is not None
    try:
        try:
            os.stat(
                LABEL_FREEZE_OUTPUT_NAME,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        except OSError as error:
            raise RuntimeError("private label freeze output validation failed") from error
        raise RuntimeError("private label freeze output validation failed")
    finally:
        os.close(parent_descriptor)


def _open_private_label_freeze_directory(
    directory: Path,
    expected_identity: tuple[int, int],
    *,
    allow_missing: bool,
) -> int | None:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory_flag:
        raise RuntimeError("private label freeze output validation failed")
    try:
        descriptor = os.open(directory, os.O_RDONLY | nofollow | directory_flag)
    except FileNotFoundError:
        if allow_missing:
            return None
        raise RuntimeError("private label freeze output validation failed") from None
    except OSError as error:
        raise RuntimeError("private label freeze output validation failed") from error
    try:
        opened = os.fstat(descriptor)
        linked = os.lstat(directory)
        opened_identity = (opened.st_dev, opened.st_ino)
        linked_identity = (linked.st_dev, linked.st_ino)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(linked.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o700
            or opened_identity != expected_identity
            or linked_identity != expected_identity
        ):
            raise RuntimeError("private label freeze output validation failed")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _cleanup_private_label_freeze_output(
    directory: Path,
    output: Path,
    expected_identity: tuple[int, int],
) -> None:
    if output != directory / LABEL_FREEZE_OUTPUT_NAME:
        raise RuntimeError("private label freeze output cleanup failed")
    parent_descriptor = _open_private_label_freeze_directory(
        directory,
        expected_identity,
        allow_missing=True,
    )
    if parent_descriptor is None:
        return
    grandparent_descriptor: int | None = None
    try:
        try:
            os.stat(
                LABEL_FREEZE_OUTPUT_NAME,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        except OSError as error:
            raise RuntimeError("private label freeze output cleanup failed") from error
        else:
            try:
                os.unlink(LABEL_FREEZE_OUTPUT_NAME, dir_fd=parent_descriptor)
            except OSError as error:
                raise RuntimeError("private label freeze output cleanup failed") from error

        nofollow = getattr(os, "O_NOFOLLOW", 0)
        directory_flag = getattr(os, "O_DIRECTORY", 0)
        grandparent_descriptor = os.open(
            directory.parent,
            os.O_RDONLY | nofollow | directory_flag,
        )
        linked = os.stat(
            directory.name,
            dir_fd=grandparent_descriptor,
            follow_symlinks=False,
        )
        opened = os.fstat(parent_descriptor)
        if (
            not stat.S_ISDIR(linked.st_mode)
            or (linked.st_dev, linked.st_ino) != expected_identity
            or (opened.st_dev, opened.st_ino) != expected_identity
        ):
            raise RuntimeError("private label freeze output cleanup failed")
        os.rmdir(directory.name, dir_fd=grandparent_descriptor)
    except RuntimeError:
        raise
    except OSError as error:
        raise RuntimeError("private label freeze output cleanup failed") from error
    finally:
        if grandparent_descriptor is not None:
            os.close(grandparent_descriptor)
        os.close(parent_descriptor)


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_digest(payload: object) -> str:
    from itda.domain.canonical import canonical_sha256

    return canonical_sha256(payload)


def _read_private_regular_file(
    parent_descriptor: int,
    name: str,
    *,
    max_bytes: int = 2_000_000,
) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow or os.open not in os.supports_dir_fd or os.stat not in os.supports_dir_fd:
        raise RuntimeError("private release authority validation failed")
    before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or not 0 < before.st_size <= max_bytes
    ):
        raise RuntimeError("private release authority validation failed")
    descriptor = os.open(name, os.O_RDONLY | nofollow, dir_fd=parent_descriptor)
    try:
        opened = os.fstat(descriptor)
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
        )
        if identity != (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
        ):
            raise RuntimeError("private release authority validation failed")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                raise RuntimeError("private release authority validation failed")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if identity != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise RuntimeError("private release authority validation failed")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _read_freeze_receipt(resources: RuntimeResources) -> tuple[LabelFreezeReceipt, bytes]:
    from itda.cli.freeze_labels import LabelFreezeReceipt
    from itda.domain.canonical import canonical_json_bytes

    parent_descriptor = _open_private_label_freeze_directory(
        resources.label_freeze_directory,
        resources.label_freeze_directory_identity,
        allow_missing=False,
    )
    assert parent_descriptor is not None
    try:
        raw = _read_private_regular_file(parent_descriptor, LABEL_FREEZE_OUTPUT_NAME)
    finally:
        os.close(parent_descriptor)
    try:
        receipt = LabelFreezeReceipt.model_validate_json(raw)
    except Exception as error:
        raise RuntimeError("private release authority validation failed") from error
    if raw != canonical_json_bytes(receipt.model_dump(mode="json")):
        raise RuntimeError("private release authority validation failed")
    frozen_at = receipt.frozen_at
    if frozen_at.tzinfo is None or frozen_at.utcoffset() != timedelta(0):
        raise RuntimeError("private release authority validation failed")
    return receipt, raw


def _candidate_manifest_for_receipt(receipt: object, *, suffix: str) -> dict[str, object]:
    from itda.analysis.text.candidate_pipeline import validate_candidate_manifest
    from itda.cli.freeze_labels import LabelFreezeReceipt

    assert isinstance(receipt, LabelFreezeReceipt)
    text_value = "합성 경주 장소는 고요한 산책과 역사적 분위기를 함께 제공한다."
    source_sha256 = _sha256_bytes(text_value.encode("utf-8"))
    candidate: dict[str, object] = {
        "candidate_id": _canonical_digest({"run": suffix, "candidate": 1}),
        "lane": "DESCRIPTION",
        "source_id": f"synthetic-source-{suffix}",
        "source_sha256": source_sha256,
        "span_id": f"synthetic-span-{suffix}",
        "slice_sha256": source_sha256,
        "start_char": 0,
        "end_char": len(text_value),
        "start_byte": 0,
        "end_byte": len(text_value.encode("utf-8")),
        "dedup_cluster_id": f"synthetic-cluster-{suffix}",
        "dedup_edges": [],
        "original_order": 0,
        "text": text_value,
        "attribute_scores": [{"attribute_id": "H1", "score": 0.8}],
        "score": 0.8,
    }
    started_at = max(receipt.frozen_at, datetime.now(UTC))
    provenance: dict[str, object] = {
        "freeze_receipt_sha256": receipt.receipt_sha256,
        "accepted_revision_set_sha256": receipt.accepted_revision_set_sha256,
        "source_manifest_sha256": receipt.source_root_sha256,
        "data_lineage_sha256": receipt.dev_lineage_sha256,
        "data_version": f"e2e-{suffix}",
        "model_id": "synthetic-offline-encoder",
        "model_revision": "synthetic-revision-v1",
        "model_config_sha256": _canonical_digest({"model": "synthetic"}),
        "tokenizer_sha256": _canonical_digest({"tokenizer": "synthetic"}),
        "weight_sha256": _canonical_digest({"weights": "synthetic"}),
        "prompt_anchor_version": "synthetic-anchor-v1",
        "preprocessing_version": "synthetic-preprocess-v1",
        "scoring_version": "synthetic-score-v1",
        "code_git_sha": "synthetic-e2e-runtime",
        "config_sha256": _canonical_digest({"run": suffix}),
        "started_at": started_at.isoformat().replace("+00:00", "Z"),
        "completed_at": (started_at + timedelta(microseconds=1)).isoformat().replace("+00:00", "Z"),
    }
    manifest: dict[str, object] = {
        "schema_version": "phase3-candidate-run-manifest-v1",
        "lanes": {
            "DESCRIPTION": {
                "status": "AVAILABLE",
                "candidates": [candidate],
                "published_evidence": [candidate],
            },
            "ODII": {"status": "MISSING", "candidates": [], "published_evidence": []},
        },
        "provenance": provenance,
    }
    provenance["output_sha256"] = _canonical_digest(manifest)
    validate_candidate_manifest(manifest)
    return manifest


def _self_authenticating_manifest(payload: dict[str, object]) -> dict[str, object]:
    result = dict(payload)
    result["manifest_sha256"] = _canonical_digest(result)
    return result


def _release_authority_graph(
    receipt: object,
    *,
    suffix: str,
    builder_principal: str,
) -> tuple[
    dict[str, bytes],
    dict[str, str],
    tuple[dict[str, object], ...],
    ProfileReleaseAuthorityRequest,
]:
    from itda.cli.freeze_labels import LabelFreezeReceipt
    from itda.contracts.profile_release_authority import ProfileReleaseAuthorityRequest
    from itda.contracts.text_evidence import (
        EvidenceLane,
        EvidenceReviewProvenance,
        LaneEvidenceStatus,
        ReviewedEvidenceLane,
        ReviewedEvidenceManifest,
    )
    from itda.domain.canonical import canonical_json_bytes

    assert isinstance(receipt, LabelFreezeReceipt)
    canonical_lineage = _canonical_digest({"canonical": suffix})
    profile_schema = _canonical_digest({"profile-schema": "v1"})
    code_sha = _canonical_digest({"code": "e2e-runtime"})
    config_sha = _canonical_digest({"config": suffix})
    source_members: list[dict[str, object]] = []
    rights_members: list[dict[str, object]] = []
    candidate_members: list[dict[str, object]] = []
    reviewed_members: list[dict[str, object]] = []
    reviewed_records: list[dict[str, object]] = []

    route_manifest = _candidate_manifest_for_receipt(receipt, suffix=suffix)
    route_output_sha = str(cast(dict[str, object], route_manifest["provenance"])["output_sha256"])
    route_provenance_payload = dict(cast(dict[str, object], route_manifest["provenance"]))
    route_provenance_payload["candidate_output_sha256"] = route_provenance_payload.pop(
        "output_sha256"
    )
    review_provenance = EvidenceReviewProvenance.model_validate(route_provenance_payload)
    finalized_at = max(receipt.frozen_at, datetime.now(UTC)) + timedelta(microseconds=2)

    for index in range(24):
        place_ref = f"DEV-{index + 1:02d}-{suffix}"
        source_sha = _canonical_digest({"source": place_ref})
        source_members.append(
            {
                "place_ref": place_ref,
                "source_sha256": source_sha,
                "description_lane": "MISSING",
                "odii_lane": "MISSING",
                "source_eligible": True,
            }
        )
        rights_members.append(
            {
                "place_ref": place_ref,
                "source_sha256": source_sha,
                "rights_sha256": _canonical_digest({"rights": place_ref}),
                "rights_eligible": True,
            }
        )
        candidate_member = {
            "place_ref": place_ref,
            "source_sha256": source_sha,
            "label_export_sha256": receipt.adjudicated_label_export_sha256,
            "profile_sha256": _canonical_digest({"profile": place_ref}),
            "description_lane": "MISSING",
            "odii_lane": "MISSING",
            "complete": True,
        }
        candidate_member["candidate_manifest_sha256"] = _canonical_digest(candidate_member)
        candidate_members.append(candidate_member)
        accepted_set = _canonical_digest({"accepted-review-set": place_ref})
        reviewed_record = ReviewedEvidenceManifest(
            candidate_manifest_sha256=str(candidate_member["candidate_manifest_sha256"]),
            accepted_review_set_sha256=accepted_set,
            provenance=review_provenance,
            lanes=(
                ReviewedEvidenceLane(
                    lane=EvidenceLane.DESCRIPTION,
                    status=LaneEvidenceStatus.MISSING,
                    evidence=(),
                    missing_reason="UPSTREAM_CANDIDATE_LANE_MISSING",
                ),
                ReviewedEvidenceLane(
                    lane=EvidenceLane.ODII,
                    status=LaneEvidenceStatus.MISSING,
                    evidence=(),
                    missing_reason="UPSTREAM_CANDIDATE_LANE_MISSING",
                ),
            ),
            finalized_by=builder_principal,
            finalized_at=finalized_at,
        ).model_dump(mode="json")
        reviewed_records.append(reviewed_record)
        reviewed_member = {
            "place_ref": place_ref,
            "candidate_manifest_sha256": candidate_member["candidate_manifest_sha256"],
            "accepted_review_set_sha256": accepted_set,
            "description_lane": "MISSING",
            "odii_lane": "MISSING",
            "evidence_eligible": True,
        }
        reviewed_member["reviewed_evidence_manifest_sha256"] = _canonical_digest(reviewed_member)
        if (
            reviewed_member["reviewed_evidence_manifest_sha256"]
            != reviewed_record["manifest_sha256"]
        ):
            reviewed_member["reviewed_evidence_manifest_sha256"] = reviewed_record[
                "manifest_sha256"
            ]
        reviewed_members.append(reviewed_member)

    source = _self_authenticating_manifest(
        {
            "schema_version": "itda.profile-release-source-authority.v1",
            "canonical_lineage_sha256": canonical_lineage,
            "dev_lineage_sha256": receipt.dev_lineage_sha256,
            "label_source_root_sha256": receipt.source_root_sha256,
            "members": source_members,
        }
    )
    rights = _self_authenticating_manifest(
        {
            "schema_version": "itda.profile-release-rights-authority.v1",
            "canonical_lineage_sha256": canonical_lineage,
            "dev_lineage_sha256": receipt.dev_lineage_sha256,
            "source_manifest_sha256": source["manifest_sha256"],
            "members": rights_members,
        }
    )
    candidate_authority = _self_authenticating_manifest(
        {
            "schema_version": "itda.profile-release-candidate-authority.v1",
            "canonical_lineage_sha256": canonical_lineage,
            "dev_lineage_sha256": receipt.dev_lineage_sha256,
            "profile_schema_sha256": profile_schema,
            "label_freeze_sha256": receipt.receipt_sha256,
            "adjudicated_label_export_sha256": receipt.adjudicated_label_export_sha256,
            "source_manifest_sha256": source["manifest_sha256"],
            "accepted_revision_set_sha256": receipt.accepted_revision_set_sha256,
            "code_sha256": code_sha,
            "config_sha256": config_sha,
            "members": candidate_members,
        }
    )
    reviewed = _self_authenticating_manifest(
        {
            "schema_version": "itda.profile-release-reviewed-authority.v1",
            "canonical_lineage_sha256": canonical_lineage,
            "dev_lineage_sha256": receipt.dev_lineage_sha256,
            "profile_schema_sha256": profile_schema,
            "candidate_manifest_sha256": candidate_authority["manifest_sha256"],
            "members": reviewed_members,
        }
    )
    if receipt.receipt_sha256 is None:
        raise RuntimeError("private release authority validation failed")
    freeze_receipt_sha256 = str(receipt.receipt_sha256)
    payloads: dict[str, bytes] = {
        "label_freeze": canonical_json_bytes(receipt.model_dump(mode="json")),
        "candidate_manifest": canonical_json_bytes(candidate_authority),
        "reviewed_manifest": canonical_json_bytes(reviewed),
        "rights_manifest": canonical_json_bytes(rights),
        "source_manifest": canonical_json_bytes(source),
        "evidence_candidates": canonical_json_bytes(route_manifest),
    }
    request = ProfileReleaseAuthorityRequest(
        release_id=f"synthetic-release-{suffix}",
        builder_principal=builder_principal,
        canonical_lineage_sha256=canonical_lineage,
        dev_lineage_sha256=receipt.dev_lineage_sha256,
        profile_schema_sha256=profile_schema,
        label_freeze_sha256=freeze_receipt_sha256,
        candidate_manifest_sha256=str(candidate_authority["manifest_sha256"]),
        reviewed_manifest_sha256=str(reviewed["manifest_sha256"]),
        rights_manifest_sha256=str(rights["manifest_sha256"]),
        source_manifest_sha256=str(source["manifest_sha256"]),
    )
    digest_values = {
        "label_freeze": freeze_receipt_sha256,
        "candidate_manifest": str(candidate_authority["manifest_sha256"]),
        "reviewed_manifest": str(reviewed["manifest_sha256"]),
        "rights_manifest": str(rights["manifest_sha256"]),
        "source_manifest": str(source["manifest_sha256"]),
        "evidence_candidates": _sha256_bytes(payloads["evidence_candidates"]),
        "candidate_freeze_parent": str(
            cast(dict[str, object], route_manifest["provenance"])["freeze_receipt_sha256"]
        ),
        "candidate_output": route_output_sha,
    }
    return payloads, digest_values, tuple(reviewed_records), request


def _write_private_file(directory: Path, name: str, payload: bytes) -> None:
    descriptor = os.open(
        directory / name,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_release_authority(
    resources: RuntimeResources,
    payloads: dict[str, bytes],
    digest_values: dict[str, str],
    request: object,
) -> tuple[Path, tuple[int, int], dict[str, str], object]:
    from itda.contracts.profile_release import ProfileReleaseCandidate
    from itda.contracts.profile_release_authority import (
        ProfileReleaseAuthorityPaths,
        ProfileReleaseAuthorityRequest,
        resolve_authoritative_profile_release_build_authority,
    )
    from itda.domain.canonical import canonical_json_bytes

    assert isinstance(request, ProfileReleaseAuthorityRequest)
    if resources.release_authority_directory is not None:
        raise RuntimeError("private release authority already published")
    parent_descriptor = _open_private_label_freeze_directory(
        resources.label_freeze_directory,
        resources.label_freeze_directory_identity,
        allow_missing=False,
    )
    assert parent_descriptor is not None
    stage = Path(
        tempfile.mkdtemp(prefix=".release-authority-stage-", dir=resources.label_freeze_directory)
    )
    active = resources.label_freeze_directory / RELEASE_AUTHORITY_DIRECTORY_NAME
    try:
        os.chmod(stage, 0o700)
        for key, payload in payloads.items():
            _write_private_file(stage, RELEASE_AUTHORITY_FILES[key], payload)
        authority_registry_id = uuid.uuid5(
            uuid.NAMESPACE_URL,
            (
                f"itda-e2e:{resources.suffix}:{request.release_id}:"
                f"{resources.phase3_role_names['builder']}"
            ),
        )
        resolution = resolve_authoritative_profile_release_build_authority(
            request=request,
            paths=ProfileReleaseAuthorityPaths(
                label_freeze=stage / RELEASE_AUTHORITY_FILES["label_freeze"],
                candidate_manifest=stage / RELEASE_AUTHORITY_FILES["candidate_manifest"],
                reviewed_manifest=stage / RELEASE_AUTHORITY_FILES["reviewed_manifest"],
                rights_manifest=stage / RELEASE_AUTHORITY_FILES["rights_manifest"],
                source_manifest=stage / RELEASE_AUTHORITY_FILES["source_manifest"],
            ),
            authority_registry_id=authority_registry_id,
            builder_database_principal=resources.phase3_role_names["builder"],
        )
        candidate = resolution.candidate
        assert isinstance(candidate, ProfileReleaseCandidate)
        build_input = candidate.model_dump(
            mode="json",
            exclude={"state", "builder_principal", "release_sha256"},
        )
        build_payload = canonical_json_bytes(build_input)
        _write_private_file(stage, RELEASE_AUTHORITY_FILES["build_input"], build_payload)
        digest_values["build_input"] = _sha256_bytes(build_payload)
        stage_descriptor = os.open(
            stage,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(stage_descriptor)
        finally:
            os.close(stage_descriptor)
        os.rename(
            stage.name,
            active.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        os.fsync(parent_descriptor)
        details = os.lstat(active)
        if not stat.S_ISDIR(details.st_mode) or stat.S_IMODE(details.st_mode) != 0o700:
            raise RuntimeError("private release authority publication failed")
        identity = (details.st_dev, details.st_ino)
        server_environment = {
            "ITDA_PROFILE_RELEASE_AUTHORITY_REGISTRY_ID": str(authority_registry_id),
            "ITDA_PHASE3_CANDIDATE_MANIFEST": str(
                active / RELEASE_AUTHORITY_FILES["evidence_candidates"]
            ),
            "ITDA_PHASE3_CANDIDATE_MANIFEST_SHA256": digest_values["evidence_candidates"],
            "ITDA_E2E_PHASE3_RELEASE_BUILD_INPUT": str(
                active / RELEASE_AUTHORITY_FILES["build_input"]
            ),
            "ITDA_E2E_PHASE3_RELEASE_BUILD_INPUT_SHA256": digest_values["build_input"],
        }
        environment_names = {
            "label_freeze": "LABEL_FREEZE",
            "candidate_manifest": "CANDIDATE",
            "reviewed_manifest": "REVIEWED",
            "rights_manifest": "RIGHTS",
            "source_manifest": "SOURCE",
        }
        for key, environment_name in environment_names.items():
            server_environment[f"ITDA_PHASE3_PROFILE_RELEASE_{environment_name}_MANIFEST"] = str(
                active / RELEASE_AUTHORITY_FILES[key]
            )
            server_environment[f"ITDA_PHASE3_PROFILE_RELEASE_{environment_name}_SHA256"] = (
                digest_values[key]
            )
        return active, identity, server_environment, resolution
    except BaseException:
        if stage.exists() and not stage.is_symlink():
            for child in stage.iterdir():
                child.unlink(missing_ok=True)
            stage.rmdir()
        raise
    finally:
        os.close(parent_descriptor)


def _cleanup_release_authority(resources: RuntimeResources) -> None:
    directory = resources.release_authority_directory
    identity = resources.release_authority_directory_identity
    if directory is None or identity is None:
        return
    if directory != resources.label_freeze_directory / RELEASE_AUTHORITY_DIRECTORY_NAME:
        raise RuntimeError("private release authority cleanup failed")
    parent_descriptor, directory_descriptor = _open_release_authority_descriptors(
        resources,
        operation="cleanup",
    )
    try:
        actual = set(os.listdir(directory_descriptor))
        expected = set(RELEASE_AUTHORITY_FILES.values())
        if actual != expected:
            raise RuntimeError("private release authority cleanup failed")
        _verify_release_authority_descriptor_identity(
            parent_descriptor,
            directory_descriptor,
            identity,
            operation="cleanup",
        )
        for name in sorted(expected):
            os.unlink(name, dir_fd=directory_descriptor)
        _verify_release_authority_descriptor_identity(
            parent_descriptor,
            directory_descriptor,
            identity,
            operation="cleanup",
        )
        os.rmdir(RELEASE_AUTHORITY_DIRECTORY_NAME, dir_fd=parent_descriptor)
    except OSError as error:
        raise RuntimeError("private release authority cleanup failed") from error
    finally:
        os.close(parent_descriptor)
        os.close(directory_descriptor)
    resources.release_authority_directory = None
    resources.release_authority_directory_identity = None
    resources.release_authority_environment.clear()
    resources.release_reviewed_records = ()
    resources.release_build_authority_resolution = None


def _verify_release_authority_descriptor_identity(
    parent_descriptor: int,
    directory_descriptor: int,
    expected_identity: tuple[int, int],
    *,
    operation: str,
) -> None:
    try:
        linked = os.stat(
            RELEASE_AUTHORITY_DIRECTORY_NAME,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        opened = os.fstat(directory_descriptor)
    except OSError as error:
        raise RuntimeError(f"private release authority {operation} failed") from error
    if (
        not stat.S_ISDIR(linked.st_mode)
        or not stat.S_ISDIR(opened.st_mode)
        or stat.S_IMODE(linked.st_mode) != 0o700
        or stat.S_IMODE(opened.st_mode) != 0o700
        or (linked.st_dev, linked.st_ino) != expected_identity
        or (opened.st_dev, opened.st_ino) != expected_identity
    ):
        raise RuntimeError(f"private release authority {operation} failed")


def _open_release_authority_descriptors(
    resources: RuntimeResources,
    *,
    operation: str,
) -> tuple[int, int]:
    identity = resources.release_authority_directory_identity
    directory = resources.release_authority_directory
    if (
        identity is None
        or directory is None
        or directory != resources.label_freeze_directory / RELEASE_AUTHORITY_DIRECTORY_NAME
    ):
        raise RuntimeError(f"private release authority {operation} failed")
    parent_descriptor = _open_private_label_freeze_directory(
        resources.label_freeze_directory,
        resources.label_freeze_directory_identity,
        allow_missing=False,
    )
    assert parent_descriptor is not None
    directory_descriptor: int | None = None
    try:
        directory_descriptor = os.open(
            RELEASE_AUTHORITY_DIRECTORY_NAME,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        _verify_release_authority_descriptor_identity(
            parent_descriptor,
            directory_descriptor,
            identity,
            operation=operation,
        )
        return parent_descriptor, directory_descriptor
    except BaseException:
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        os.close(parent_descriptor)
        raise


def _checked(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    runner: Callable[..., subprocess.CompletedProcess[str]],
    timeout: float = DEFAULT_PREREQUISITE_TIMEOUT_SECONDS,
) -> str:
    try:
        completed = runner(
            command,
            cwd=cwd,
            environment=environment,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise PreflightError(
            f"prerequisite command timed out after {timeout:.0f}s: {' '.join(command)}"
        ) from error
    except (OSError, subprocess.SubprocessError) as error:
        raise PreflightError(f"prerequisite command unavailable: {' '.join(command)}") from error
    if completed.returncode != 0:
        details = "\n".join(
            part.strip() for part in (completed.stdout, completed.stderr) if part.strip()
        )
        suffix = f": {details}" if details else ""
        raise PreflightError(f"prerequisite command failed ({' '.join(command)}){suffix}")
    return completed.stdout.strip()


def _require_offline_boundary(environment: Mapping[str, str]) -> None:
    for name, expected in _REQUIRED_ENVIRONMENT.items():
        actual = environment.get(name)
        if actual != expected:
            raise PreflightError(f"{name} must be exactly {expected!r}, got {actual!r}")
    docker_host = environment.get("DOCKER_HOST", "")
    if docker_host and not docker_host.startswith("unix://"):
        raise PreflightError("DOCKER_HOST must resolve to a local Unix socket")
    docker_context = environment.get("DOCKER_CONTEXT", "")
    if docker_context and docker_context not in {"default", "desktop-linux"}:
        raise PreflightError(
            "DOCKER_CONTEXT must be an approved local context: default or desktop-linux"
        )


def _verify_local_docker_endpoint(
    *,
    environment: Mapping[str, str],
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    output = _checked(
        [
            "docker",
            "context",
            "inspect",
            "--format",
            "{{json .Endpoints.docker.Host}}",
        ],
        cwd=REPOSITORY_ROOT,
        environment=environment,
        runner=runner,
    )
    try:
        endpoint = json.loads(output)
    except json.JSONDecodeError as error:
        raise PreflightError("Docker context endpoint inspection returned invalid JSON") from error
    if not isinstance(endpoint, str) or not endpoint.startswith("unix://"):
        raise PreflightError("Docker context must resolve to a local Unix socket")


def _normalized_version(tool: str, output: str) -> str:
    value = output.strip()
    if tool == "python":
        return value.removeprefix("Python ").strip()
    if tool == "uv":
        return value.removeprefix("uv ").strip().split(maxsplit=1)[0]
    if tool == "node":
        return value.removeprefix("v").strip()
    return value


def _verify_tools(
    *,
    environment: Mapping[str, str],
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    for tool, version in _PINNED_TOOLS.items():
        install_root_output = _checked(
            ["mise", "where", f"{tool}@{version}"],
            cwd=REPOSITORY_ROOT,
            environment=environment,
            runner=runner,
        )
        executable_output = _checked(
            ["mise", "which", tool],
            cwd=REPOSITORY_ROOT,
            environment=environment,
            runner=runner,
        )
        install_root = Path(install_root_output).resolve()
        executable = Path(executable_output).resolve()
        try:
            executable.relative_to(install_root)
        except ValueError as error:
            raise PreflightError(
                f"{tool} does not resolve from pinned mise install {install_root}"
            ) from error
        actual = _normalized_version(
            tool,
            _checked(
                [tool, "--version"],
                cwd=REPOSITORY_ROOT,
                environment=environment,
                runner=runner,
            ),
        )
        if actual != version:
            raise PreflightError(f"{tool} {version} required, found {actual}")


def _verify_backend_environment(
    *,
    environment: Mapping[str, str],
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    environment_root = Path(environment.get("UV_PROJECT_ENVIRONMENT", ".venv"))
    if not environment_root.is_absolute():
        environment_root = BACKEND_ROOT / environment_root
    _checked(
        ["uv", "pip", "check", "--python", str(environment_root / "bin" / "python")],
        cwd=REPOSITORY_ROOT,
        environment=environment,
        runner=runner,
        timeout=PREREQUISITE_TIMEOUT_SECONDS,
    )


def _verify_postgres_image(
    *,
    environment: Mapping[str, str],
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    try:
        output = _checked(
            [
                "docker",
                "image",
                "inspect",
                POSTGRES_IMAGE,
                "--format",
                "{{json .}}",
            ],
            cwd=REPOSITORY_ROOT,
            environment=environment,
            runner=runner,
            timeout=DEFAULT_PREREQUISITE_TIMEOUT_SECONDS,
        )
    except PreflightError as error:
        raise PreflightError(f"PostgreSQL 17.10 pinned image inspection failed: {error}") from error
    try:
        inspected = json.loads(output)
    except json.JSONDecodeError as error:
        raise PreflightError("PostgreSQL image inspection returned invalid JSON") from error
    repo_digests = inspected.get("RepoDigests", [])
    if not isinstance(repo_digests, list) or not any(
        str(item).endswith(f"@sha256:{POSTGRES_IMAGE_DIGEST}") for item in repo_digests
    ):
        raise PreflightError(
            f"PostgreSQL 17.10 image digest {POSTGRES_IMAGE_DIGEST} is not installed"
        )


def _verify_playwright_bundle(
    *,
    environment: Mapping[str, str],
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> PreflightReport:
    output = _checked(
        ["node", "--input-type=commonjs", "--eval", PLAYWRIGHT_BUNDLE_PROBE],
        cwd=WEB_ROOT,
        environment=environment,
        runner=runner,
        timeout=PREREQUISITE_TIMEOUT_SECONDS,
    )
    try:
        payload = json.loads(output)
    except json.JSONDecodeError as error:
        raise PreflightError("Playwright bundle probe returned invalid JSON") from error
    for package_name, key in (
        ("@playwright/test", "testVersion"),
        ("playwright-core", "coreVersion"),
    ):
        actual = payload.get(key)
        if actual != PLAYWRIGHT_VERSION:
            raise PreflightError(f"{package_name} {PLAYWRIGHT_VERSION} required, found {actual!r}")
    browser_entries = payload.get("browsers")
    if not isinstance(browser_entries, list):
        raise PreflightError("Playwright browsers.json metadata is missing")
    by_name = {
        entry.get("name"): entry
        for entry in browser_entries
        if isinstance(entry, dict) and isinstance(entry.get("name"), str)
    }
    executable_paths: dict[str, Path] = {}
    for name in ("chromium", "chromium-headless-shell"):
        entry = by_name.get(name)
        if entry is None or entry.get("revision") != PLAYWRIGHT_CHROMIUM_REVISION:
            actual_revision = entry.get("revision") if entry else None
            raise PreflightError(
                f"{name} revision {PLAYWRIGHT_CHROMIUM_REVISION} required, "
                f"found {actual_revision!r}"
            )
        raw_path = entry.get("executablePath")
        executable_path = Path(raw_path) if isinstance(raw_path, str) else Path()
        if not raw_path or not executable_path.is_file() or not os.access(executable_path, os.X_OK):
            raise PreflightError(
                f"{name} revision {PLAYWRIGHT_CHROMIUM_REVISION} executable "
                f"is missing or not executable: {raw_path!r}"
            )
        executable_paths[name] = executable_path
    if executable_paths["chromium"] == executable_paths["chromium-headless-shell"]:
        raise PreflightError("Chromium and chromium-headless-shell executables must be distinct")
    return PreflightReport(
        chromium_revision=PLAYWRIGHT_CHROMIUM_REVISION,
        chromium_executable=executable_paths["chromium"],
        chromium_headless_shell_executable=executable_paths["chromium-headless-shell"],
    )


def preflight(
    *,
    environment: Mapping[str, str],
    runner: Callable[..., subprocess.CompletedProcess[str]] = _default_runner,
) -> PreflightReport:
    """Verify all immutable prerequisites before any E2E side effect."""

    _require_offline_boundary(environment)
    safe_environment = _safe_environment(environment)
    _verify_tools(environment=safe_environment, runner=runner)
    _verify_backend_environment(environment=safe_environment, runner=runner)
    _verify_local_docker_endpoint(environment=safe_environment, runner=runner)
    _verify_postgres_image(environment=safe_environment, runner=runner)
    return _verify_playwright_bundle(environment=safe_environment, runner=runner)


def _available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind((API_HOST, 0))
        return int(listener.getsockname()[1])


def _identifier_fragment(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9_]", "_", value)
    if not normalized:
        return "run"
    if len(normalized) <= 20:
        return normalized
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]
    return f"{normalized[:9]}_{digest}"


def _phase3_capabilities(environment: Mapping[str, str]) -> dict[str, str]:
    provided = {
        capability: environment.get(f"ITDA_E2E_PHASE3_{capability.upper()}_CAPABILITY")
        for capability in PHASE3_CAPABILITIES
    }
    if not any(value is not None for value in provided.values()):
        return {capability: secrets.token_urlsafe(32) for capability in PHASE3_CAPABILITIES}
    if any(value is None or len(value) < 32 for value in provided.values()):
        raise RuntimeError("all Phase 3 E2E capabilities must be supplied together")
    values = [value for value in provided.values() if value is not None]
    if len(set(values)) != len(PHASE3_CAPABILITIES):
        raise RuntimeError("Phase 3 E2E capabilities must be distinct")
    return {capability: value for capability, value in provided.items() if value is not None}


class DefaultRuntimeLifecycle:
    """Concrete local resource lifecycle used after the immutable preflight."""

    def __init__(
        self,
        environment: Mapping[str, str],
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._environment = dict(environment)
        self._cleanup_deadline: float | None = None
        self._stop_requested = threading.Event()
        self._clock = clock
        self._sleep = sleep

    def set_stop_event(self, stop_requested: threading.Event) -> None:
        self._stop_requested = stop_requested

    def _raise_if_cancelled(self) -> None:
        if self._stop_requested.is_set():
            raise StartupCancelled("E2E startup interrupted")

    def begin_cleanup(self) -> None:
        self._cleanup_deadline = self._clock() + CLEANUP_BUDGET_SECONDS

    def _cleanup_timeout(self, maximum: float) -> float:
        if self._cleanup_deadline is None:
            return maximum
        remaining = self._cleanup_deadline - self._clock()
        if remaining <= 0:
            raise TimeoutError(f"E2E cleanup exceeded {CLEANUP_BUDGET_SECONDS:.0f}-second budget")
        return min(maximum, remaining)

    def _database_cleanup_timeout(self, maximum: float) -> float:
        if self._cleanup_deadline is None:
            return maximum
        remaining = self._cleanup_deadline - self._clock() - COMPOSE_DOWN_RESERVED_SECONDS
        if remaining <= 0:
            raise TimeoutError(
                "database cleanup exhausted its budget while reserving "
                f"{COMPOSE_DOWN_RESERVED_SECONDS:.0f}s for Compose down"
            )
        return min(maximum, remaining)

    def allocate(self) -> RuntimeResources:
        from psycopg.conninfo import make_conninfo

        run_id = _identifier_fragment(self._environment.get("ITDA_E2E_RUN_ID", "run"))
        suffix = f"{run_id}_{os.getpid()}_{uuid.uuid4().hex[:8]}"
        project_name = f"itda_e2e_{suffix}"[:63]
        database_name = f"itda_e2e_{suffix}"[:63]
        admin_name = f"itda_admin_{suffix}"[:63]
        runtime_name = f"itda_runtime_{suffix}"[:63]
        admin_password = secrets.token_urlsafe(24)
        runtime_password = secrets.token_urlsafe(24)
        profile_release_authority_password = secrets.token_urlsafe(24)
        photo_service_password = secrets.token_urlsafe(24)
        profile_session_service_password = secrets.token_urlsafe(24)
        daily_glm_service_password = secrets.token_urlsafe(24)
        profile_session_current_key = (
            base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
        )
        profile_session_previous_key = (
            base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
        )
        phase3_role_names = {
            capability: f"itda_label_{capability}_{suffix}"[:63]
            for capability in PHASE3_CAPABILITIES
        }
        phase3_capabilities = _phase3_capabilities(self._environment)
        phase3_passwords = {
            capability: secrets.token_urlsafe(24) for capability in PHASE3_CAPABILITIES
        }
        port = _available_port()
        safe_environment = _safe_environment(self._environment)
        compose_environment = {
            **safe_environment,
            "COMPOSE_PROJECT_NAME": project_name,
            "ITDA_POSTGRES_ADMIN_PASSWORD": admin_password,
            "ITDA_POSTGRES_ADMIN_USER": admin_name,
            "ITDA_POSTGRES_DB": database_name,
            "ITDA_POSTGRES_PORT": str(port),
        }
        admin_dsn = make_conninfo(
            host=API_HOST,
            port=port,
            dbname=database_name,
            user=admin_name,
            password=admin_password,
            connect_timeout=DATABASE_CONNECT_TIMEOUT_SECONDS,
            options=DATABASE_SESSION_OPTIONS,
        )
        admin_postgres_dsn = make_conninfo(
            host=API_HOST,
            port=port,
            dbname="postgres",
            user=admin_name,
            password=admin_password,
            connect_timeout=DATABASE_CONNECT_TIMEOUT_SECONDS,
            options=DATABASE_SESSION_OPTIONS,
        )
        runtime_dsn = make_conninfo(
            host=API_HOST,
            port=port,
            dbname=database_name,
            user=runtime_name,
            password=runtime_password,
            connect_timeout=DATABASE_CONNECT_TIMEOUT_SECONDS,
            options=DATABASE_SESSION_OPTIONS,
        )
        profile_release_authority_dsn = make_conninfo(
            host=API_HOST,
            port=port,
            dbname=database_name,
            user=PROFILE_RELEASE_AUTHORITY_SERVICE_ROLE,
            password=profile_release_authority_password,
            connect_timeout=DATABASE_CONNECT_TIMEOUT_SECONDS,
            options=DATABASE_SESSION_OPTIONS,
        )
        phase3_dsns = {
            capability: make_conninfo(
                host=API_HOST,
                port=port,
                dbname=database_name,
                user=phase3_role_names[capability],
                password=phase3_passwords[capability],
                connect_timeout=DATABASE_CONNECT_TIMEOUT_SECONDS,
                options=DATABASE_SESSION_OPTIONS,
            )
            for capability in PHASE3_CAPABILITIES
        }
        photo_service_dsn = make_conninfo(
            host=API_HOST,
            port=port,
            dbname=database_name,
            user=PHOTO_AUTHORITY_SERVICE_ROLE,
            password=photo_service_password,
            connect_timeout=DATABASE_CONNECT_TIMEOUT_SECONDS,
            options=DATABASE_SESSION_OPTIONS,
        )
        profile_session_service_dsn = make_conninfo(
            host=API_HOST,
            port=port,
            dbname=database_name,
            user=PROFILE_SESSION_SERVICE_ROLE,
            password=profile_session_service_password,
            connect_timeout=DATABASE_CONNECT_TIMEOUT_SECONDS,
            options=DATABASE_SESSION_OPTIONS,
        )
        label_freeze_directory, label_freeze_directory_identity = _private_label_freeze_directory()
        photo_quarantine_directory, photo_quarantine_directory_identity = (
            _private_runtime_directory("itda-phase6-quarantine-")
        )
        try:
            label_freeze_output = label_freeze_directory / LABEL_FREEZE_OUTPUT_NAME
            resources = RuntimeResources(
                suffix=suffix,
                project_name=project_name,
                database_name=database_name,
                admin_name=admin_name,
                runtime_name=runtime_name,
                port=port,
                phase3_role_names=phase3_role_names,
                phase3_capabilities=phase3_capabilities,
                phase3_passwords=phase3_passwords,
                phase3_dsns=phase3_dsns,
                admin_password=admin_password,
                runtime_password=runtime_password,
                profile_release_authority_password=profile_release_authority_password,
                photo_service_password=photo_service_password,
                profile_session_service_password=profile_session_service_password,
                daily_glm_service_password=daily_glm_service_password,
                profile_session_current_key=profile_session_current_key,
                profile_session_previous_key=profile_session_previous_key,
                compose_environment=compose_environment,
                admin_dsn=admin_dsn,
                admin_postgres_dsn=admin_postgres_dsn,
                runtime_dsn=runtime_dsn,
                profile_release_authority_dsn=profile_release_authority_dsn,
                label_freeze_directory=label_freeze_directory,
                label_freeze_output=label_freeze_output,
                label_freeze_directory_identity=label_freeze_directory_identity,
                photo_service_dsn=photo_service_dsn,
                profile_session_service_dsn=profile_session_service_dsn,
                photo_quarantine_directory=photo_quarantine_directory,
                photo_quarantine_directory_identity=photo_quarantine_directory_identity,
            )
            _validate_label_freeze_output(resources)
            return resources
        except BaseException as error:
            try:
                _cleanup_private_label_freeze_output(
                    label_freeze_directory,
                    label_freeze_output,
                    label_freeze_directory_identity,
                )
            except BaseException:
                error.add_note("private label freeze output cleanup also failed")
            try:
                _cleanup_private_photo_quarantine_directory(
                    photo_quarantine_directory,
                    photo_quarantine_directory_identity,
                )
            except BaseException:
                error.add_note("private photo quarantine cleanup also failed")
            raise

    def _compose(
        self,
        resources: RuntimeResources,
        arguments: Sequence[str],
        *,
        timeout: float,
    ) -> str:
        try:
            completed = subprocess.run(
                [
                    "docker",
                    "compose",
                    "-f",
                    str(COMPOSE_FILE),
                    *arguments,
                ],
                cwd=REPOSITORY_ROOT,
                env=resources.compose_environment,
                capture_output=True,
                check=False,
                text=True,
                timeout=timeout,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise RuntimeError("docker compose invocation failed") from error
        if completed.returncode == 0:
            return completed.stdout.strip()
        details = "\n".join(
            part.strip() for part in (completed.stdout, completed.stderr) if part.strip()
        )
        raise RuntimeError(
            redact_diagnostic(
                f"docker compose exited {completed.returncode}: {details}",
                resources.secrets,
            )
        )

    def _run_startup_process(
        self,
        command: Sequence[str],
        *,
        environment: Mapping[str, str],
        timeout: float,
        started_sentinel: str | None = None,
        child_work_marker: str | None = None,
    ) -> None:
        try:
            process = subprocess.Popen(
                list(command),
                cwd=REPOSITORY_ROOT,
                env=dict(environment),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=False,
            )
        except OSError as error:
            raise RuntimeError(f"startup command unavailable: {' '.join(command)}") from error
        output_lines: list[str] = []
        work_observed = threading.Event()

        def consume_output() -> None:
            assert process.stdout is not None
            for line in process.stdout:
                output_lines.append(line)
                if child_work_marker is not None and line.strip() == child_work_marker:
                    work_observed.set()

        reader = threading.Thread(target=consume_output, daemon=True)
        reader.start()
        sentinel_emitted = False

        def emit_observed_sentinel() -> None:
            nonlocal sentinel_emitted
            if started_sentinel and work_observed.is_set() and not sentinel_emitted:
                print(started_sentinel, flush=True)
                sentinel_emitted = True

        deadline = self._clock() + timeout
        try:
            while True:
                self._raise_if_cancelled()
                emit_observed_sentinel()
                returncode = process.poll()
                if returncode is not None:
                    reader.join(timeout=5)
                    emit_observed_sentinel()
                    if returncode == 0:
                        if started_sentinel and not sentinel_emitted:
                            raise RuntimeError(
                                "startup command completed before its active-work marker"
                            )
                        return
                    details = "".join(output_lines).strip()
                    raise RuntimeError(
                        redact_diagnostic(
                            f"startup command exited {returncode}: {details}",
                            tuple(
                                value
                                for key, value in environment.items()
                                if "PASSWORD" in key or key == "ITDA_DATABASE_URL"
                            ),
                        )
                    )
                if self._clock() >= deadline:
                    raise TimeoutError(
                        f"startup command timed out after {timeout:.0f}s: {' '.join(command)}"
                    )
                self._sleep(STARTUP_POLL_SECONDS)
        except (StartupCancelled, TimeoutError):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            raise
        finally:
            reader.join(timeout=5)

    def compose_up(self, resources: object) -> None:
        import psycopg

        assert isinstance(resources, RuntimeResources)
        self._run_startup_process(
            [
                "docker",
                "compose",
                "-f",
                str(COMPOSE_FILE),
                "up",
                "--pull",
                "never",
                "-d",
                "--wait",
                "--wait-timeout",
                str(int(COMPOSE_UP_TIMEOUT_SECONDS)),
                "postgres",
            ],
            environment=resources.compose_environment,
            timeout=COMPOSE_UP_TIMEOUT_SECONDS,
        )
        if self._environment.get("ITDA_E2E_INTERRUPT_PHASE") == "compose-readiness":
            running_container = self._compose(
                resources,
                ["ps", "--status", "running", "--quiet", "postgres"],
                timeout=COMPOSE_ACTIVE_PROBE_TIMEOUT_SECONDS,
            )
            if not running_container:
                raise RuntimeError(
                    "Compose reported success without an active PostgreSQL container"
                )
            print(LIFECYCLE_INTERRUPT_SENTINELS["compose-readiness"], flush=True)
        deadline = self._clock() + POSTGRES_READY_TIMEOUT_SECONDS
        last_error: Exception | None = None
        while self._clock() < deadline:
            self._raise_if_cancelled()
            try:
                with psycopg.connect(
                    resources.admin_dsn,
                    connect_timeout=DATABASE_CONNECT_TIMEOUT_SECONDS,
                    options=DATABASE_SESSION_OPTIONS,
                ) as connection:
                    version = connection.execute(
                        "SELECT current_setting('server_version_num')::integer"
                    ).fetchone()
                    if version is not None and version[0] // 10000 == 17:
                        return
            except psycopg.Error as error:
                last_error = error
            self._sleep(STARTUP_POLL_SECONDS)
        raise TimeoutError(
            f"PostgreSQL 17 did not become ready within "
            f"{POSTGRES_READY_TIMEOUT_SECONDS:.0f} seconds"
        ) from last_error

    def migrate(self, resources: object) -> None:
        import psycopg
        from psycopg import sql

        assert isinstance(resources, RuntimeResources)
        self._raise_if_cancelled()
        with psycopg.connect(
            resources.admin_dsn,
            autocommit=True,
            connect_timeout=DATABASE_CONNECT_TIMEOUT_SECONDS,
            options=DATABASE_SESSION_OPTIONS,
        ) as connection:
            self._raise_if_cancelled()
            for authority_role in (
                PROFILE_RELEASE_WRITE_AUTHORITY_ROLE,
                PHOTO_WRITE_AUTHORITY_ROLE,
                PROFILE_SESSION_OWNER_ROLE,
                DAILY_GLM_WRITE_AUTHORITY_ROLE,
            ):
                connection.execute(
                    sql.SQL(
                        "CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                        "NOREPLICATION NOBYPASSRLS NOINHERIT"
                    ).format(sql.Identifier(authority_role))
                )
            role_credentials = (
                (resources.runtime_name, resources.runtime_password),
                (
                    PROFILE_RELEASE_AUTHORITY_SERVICE_ROLE,
                    resources.profile_release_authority_password,
                ),
                (PHOTO_AUTHORITY_SERVICE_ROLE, resources.photo_service_password),
                (
                    PROFILE_SESSION_SERVICE_ROLE,
                    resources.profile_session_service_password,
                ),
                (
                    DAILY_GLM_SERVICE_ROLE,
                    resources.daily_glm_service_password,
                ),
                *(
                    (
                        resources.phase3_role_names[capability],
                        resources.phase3_passwords[capability],
                    )
                    for capability in PHASE3_CAPABILITIES
                ),
            )
            for role_name, password in role_credentials:
                connection.execute(
                    sql.SQL(
                        "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB "
                        "NOCREATEROLE NOREPLICATION NOINHERIT"
                    ).format(
                        sql.Identifier(role_name),
                        sql.Literal(password),
                    )
                )
                self._raise_if_cancelled()
                connection.execute(
                    sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                        sql.Identifier(resources.database_name),
                        sql.Identifier(role_name),
                    )
                )
                self._raise_if_cancelled()
        migration_environment = {
            **_safe_environment(self._environment),
            "ITDA_DATABASE_URL": resources.admin_dsn,
            "ITDA_RUNTIME_ROLE": resources.runtime_name,
            "ITDA_DATABASE_NAME": resources.database_name,
            **{
                f"ITDA_LABEL_{capability.upper()}_ROLE": role_name
                for capability, role_name in resources.phase3_role_names.items()
            },
            "PYTHONPATH": str(BACKEND_ROOT / "src"),
        }
        migration_script = f"""
import os
import time

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine

from itda.db.session import sqlalchemy_url_from_dsn

config = Config({str(ALEMBIC_INI)!r})
database_url = sqlalchemy_url_from_dsn(
    os.environ["ITDA_DATABASE_URL"]
).render_as_string(hide_password=False)
config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
config.attributes["runtime_role"] = os.environ["ITDA_RUNTIME_ROLE"]
config.attributes["database_name"] = os.environ["ITDA_DATABASE_NAME"]
config.attributes["label_evaluator_a_role"] = os.environ["ITDA_LABEL_EVALUATOR_A_ROLE"]
config.attributes["label_evaluator_b_role"] = os.environ["ITDA_LABEL_EVALUATOR_B_ROLE"]
config.attributes["label_evaluator_c_role"] = os.environ["ITDA_LABEL_EVALUATOR_C_ROLE"]
config.attributes["label_adjudicator_role"] = os.environ["ITDA_LABEL_ADJUDICATOR_ROLE"]
config.attributes["label_model_runner_role"] = os.environ["ITDA_LABEL_MODEL_RUNNER_ROLE"]
config.attributes["label_builder_role"] = os.environ["ITDA_LABEL_BUILDER_ROLE"]
config.attributes["label_approver_role"] = os.environ["ITDA_LABEL_APPROVER_ROLE"]
engine = create_engine(database_url)
with engine.connect() as connection, connection.begin():
    MigrationContext.configure(connection).get_current_heads()
    print({MIGRATION_CHILD_WORK_MARKER!r}, flush=True)
    if os.environ.get("ITDA_E2E_INTERRUPT_PHASE") == "migration":
        while True:
            time.sleep(1)
engine.dispose()
command.upgrade(config, "head")
""".strip()
        self._run_startup_process(
            [sys.executable, "-c", migration_script],
            environment=migration_environment,
            timeout=MIGRATION_TIMEOUT_SECONDS,
            started_sentinel=(
                LIFECYCLE_INTERRUPT_SENTINELS["migration"]
                if self._environment.get("ITDA_E2E_INTERRUPT_PHASE") == "migration"
                else None
            ),
            child_work_marker=(
                MIGRATION_CHILD_WORK_MARKER
                if self._environment.get("ITDA_E2E_INTERRUPT_PHASE") == "migration"
                else None
            ),
        )

    def verify_runtime_role(self, resources: object) -> None:
        import psycopg

        assert isinstance(resources, RuntimeResources)
        self._raise_if_cancelled()
        with psycopg.connect(
            resources.runtime_dsn,
            connect_timeout=DATABASE_CONNECT_TIMEOUT_SECONDS,
            options=DATABASE_SESSION_OPTIONS,
        ) as connection:
            self._raise_if_cancelled()
            row = connection.execute("SELECT count(*) FROM preference_profiles").fetchone()
            self._raise_if_cancelled()
            if row != (0,):
                raise RuntimeError("runtime role app profile smoke test returned unexpected rows")

        privilege_probes = {
            "evaluator_a": (
                "SELECT has_schema_privilege(current_user, 'dev_eval', 'USAGE'), "
                "has_function_privilege(current_user, "
                "'dev_eval.submit_label_revision_v1(jsonb)', 'EXECUTE'), "
                "has_table_privilege(current_user, "
                "'dev_eval.own_label_revisions_v1', 'SELECT')"
            ),
            "evaluator_b": (
                "SELECT has_schema_privilege(current_user, 'dev_eval', 'USAGE'), "
                "has_function_privilege(current_user, "
                "'dev_eval.submit_label_revision_v1(jsonb)', 'EXECUTE'), "
                "has_table_privilege(current_user, "
                "'dev_eval.own_label_revisions_v1', 'SELECT')"
            ),
            "evaluator_c": (
                "SELECT has_schema_privilege(current_user, 'dev_eval', 'USAGE'), "
                "has_function_privilege(current_user, "
                "'dev_eval.submit_label_revision_v1(jsonb)', 'EXECUTE'), "
                "has_table_privilege(current_user, "
                "'dev_eval.own_label_revisions_v1', 'SELECT')"
            ),
            "adjudicator": (
                "SELECT has_function_privilege(current_user, "
                "'dev_eval.get_label_revision_v1(text)', 'EXECUTE'), "
                "has_function_privilege(current_user, "
                "'dev_eval.select_accepted_label_revision_v1(text,text,timestamp with time zone)', "
                "'EXECUTE'), true"
            ),
            "builder": (
                "SELECT has_schema_privilege(current_user, 'dev_eval', 'USAGE'), "
                "has_table_privilege(current_user, "
                "'dev_eval.label_submission_status_v1', 'SELECT'), true"
            ),
        }
        for capability, dsn in resources.phase3_dsns.items():
            self._raise_if_cancelled()
            with psycopg.connect(
                dsn,
                connect_timeout=DATABASE_CONNECT_TIMEOUT_SECONDS,
                options=DATABASE_SESSION_OPTIONS,
            ) as connection:
                identity = connection.execute("SELECT session_user").fetchone()
                if identity != (resources.phase3_role_names[capability],):
                    raise RuntimeError("Phase 3 role session identity verification failed")
                probe = privilege_probes.get(capability)
                if probe is not None and connection.execute(probe).fetchone() != (
                    True,
                    True,
                    True,
                ):
                    raise RuntimeError("Phase 3 migration grant verification failed")

        # Phase 6 exclusive photo authority: the service DSN must be the
        # fixed principal, hold only the v2 EXECUTE allowlist, and keep the
        # runtime application DSN fully separated from photo mutation.
        assert isinstance(resources, RuntimeResources)
        self._raise_if_cancelled()
        with psycopg.connect(
            resources.photo_service_dsn,
            connect_timeout=DATABASE_CONNECT_TIMEOUT_SECONDS,
            options=DATABASE_SESSION_OPTIONS,
        ) as connection:
            identity = connection.execute("SELECT session_user").fetchone()
            if identity != (PHOTO_AUTHORITY_SERVICE_ROLE,):
                raise RuntimeError("photo service DSN identity verification failed")
            topology = connection.execute(
                "SELECT rolcanlogin, rolinherit, rolsuper, rolcreatedb, "
                "rolcreaterole, rolreplication, rolbypassrls "
                "FROM pg_catalog.pg_roles WHERE rolname = %s",
                (PHOTO_AUTHORITY_SERVICE_ROLE,),
            ).fetchone()
            if topology != (True, False, False, False, False, False, False):
                raise RuntimeError("photo service role flags verification failed")
            owner_topology = connection.execute(
                "SELECT rolcanlogin, rolinherit, rolsuper, rolcreatedb, "
                "rolcreaterole, rolreplication, rolbypassrls "
                "FROM pg_catalog.pg_roles WHERE rolname = %s",
                (PHOTO_WRITE_AUTHORITY_ROLE,),
            ).fetchone()
            if owner_topology != (False, False, False, False, False, False, False):
                raise RuntimeError("photo owner role flags verification failed")
            roles = (
                PHOTO_WRITE_AUTHORITY_ROLE,
                PHOTO_AUTHORITY_SERVICE_ROLE,
                resources.runtime_name,
                resources.phase3_role_names["builder"],
            )
            pairs = tuple(
                (member, granted) for member in roles for granted in roles if member != granted
            )
            related = connection.execute(
                "SELECT count(*) FROM unnest(%s::text[], %s::text[]) "
                "AS pair(member, granted) "
                "WHERE pg_catalog.pg_has_role(pair.member, pair.granted, 'MEMBER')",
                (
                    [member for member, _granted in pairs],
                    [granted for _member, granted in pairs],
                ),
            ).fetchone()
            if related != (0,):
                raise RuntimeError("photo role membership closure verification failed")
            required_relations = (
                "photo_jobs",
                "photo_job_dispatch_markers",
                "photo_trait_candidates",
                "photo_confirmed_traits",
                "photo_deletion_ledger",
                "photo_review_drafts",
                "photo_confirmation_receipts",
                "photo_job_filesystem_bindings",
                "photo_job_image_slots",
            )
            owner = connection.execute(
                "SELECT count(*) FROM pg_catalog.pg_class c "
                "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
                "JOIN pg_catalog.pg_roles r ON r.oid=c.relowner "
                "WHERE n.nspname='dev_eval' AND c.relname=ANY(%s) "
                "AND r.rolname=%s",
                (list(required_relations), PHOTO_WRITE_AUTHORITY_ROLE),
            ).fetchone()
            if owner != (len(required_relations),):
                raise RuntimeError("photo lifecycle ownership verification failed")
            allowed_photo_signatures = (
                "create_photo_job_v3(text,text,text)",
                "claim_photo_job_filesystem_binding_v3(text,text)",
                "read_photo_job_filesystem_binding_v3(text,text)",
                "lock_photo_job_operation_v3(text,text,text)",
                "list_photo_cleanup_candidates_v3()",
                "transition_photo_job_nonterminal_v3(text,text,text,text,timestamptz)",
                "append_photo_deletion_ledger_v3(text,text,text,text,text,integer,text)",
                "finalize_photo_job_terminal_v3(text,text,text,text,text,text,text,text)",
                "finalize_photo_job_unbound_explicit_deletion_v3(text,text)",
                "record_photo_dispatch_marker_v3(text,text,integer,text)",
                "record_photo_candidate_batch_v3(text,text,text[],text[],text[],text[])",
                "annotate_photo_candidate_v3(text,text,text,text,boolean)",
                "save_photo_review_draft_v3(text,text,text,text[],text[],text[],boolean[])",
                "discard_photo_review_draft_v3(text,text)",
                "confirm_photo_traits_v3"
                "(text,text,text,text[],text[],text[],boolean[],boolean[],text)",
                "read_photo_job_v2(text,text)",
                "list_photo_candidates_v2(text,text)",
                "list_photo_confirmed_traits_v2(text,text)",
                "list_photo_dispatch_markers_v2(text,text)",
                "read_photo_review_draft_v2(text,text)",
                "read_photo_confirmation_receipt_v2(text,text,text)",
                "read_photo_recommendation_projection_v1(text,text)",
                "list_photo_deletion_ledger_v3(text,text)",
                "read_photo_cleanup_status_v3(text,text)",
                "complete_photo_filesystem_cleanup_v3(text,text,text,text)",
                "pending_photo_filesystem_release_v3(text,text,text,text)",
                "read_photo_filesystem_release_v3(text,text)",
                "reserve_photo_image_slot_v3(text,text,integer,text,text)",
                "commit_photo_image_slot_v3(text,text,integer,text,integer)",
                "read_photo_image_slots_v3(text,text)",
            )
            allowed_photo_procedures = tuple(
                f"dev_eval.{signature}" for signature in allowed_photo_signatures
            )
            for signature in allowed_photo_signatures:
                granted = connection.execute(
                    "SELECT has_function_privilege(current_user, %s, 'EXECUTE')",
                    (f"dev_eval.{signature}",),
                ).fetchone()
                if granted != (True,):
                    raise RuntimeError("photo function EXECUTE verification failed")
            allowed_acl = connection.execute(
                "SELECT count(*) FILTER (WHERE a.grantee=(SELECT oid FROM "
                "pg_catalog.pg_roles WHERE rolname=%s) "
                "AND a.privilege_type='EXECUTE' AND a.grantor=p.proowner "
                "AND NOT a.is_grantable), "
                "count(*) FILTER (WHERE NOT (a.grantee=(SELECT oid FROM "
                "pg_catalog.pg_roles WHERE rolname=%s) "
                "AND a.privilege_type='EXECUTE' AND a.grantor=p.proowner "
                "AND NOT a.is_grantable)) "
                "FROM pg_catalog.pg_proc p "
                "JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace "
                "CROSS JOIN LATERAL pg_catalog.aclexplode("
                "COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))) a "
                "WHERE n.nspname='dev_eval' "
                "AND p.oid=ANY(CAST(%s AS pg_catalog.regprocedure[]))",
                (
                    PHOTO_AUTHORITY_SERVICE_ROLE,
                    PHOTO_AUTHORITY_SERVICE_ROLE,
                    list(allowed_photo_procedures),
                ),
            ).fetchone()
            if allowed_acl != (len(allowed_photo_procedures), 0):
                raise RuntimeError("photo function EXECUTE ACL verification failed")
            owner_only_procedures = (
                "dev_eval.transition_photo_job_status_v1(text,text,text,text,timestamptz)",
                "dev_eval.claim_photo_job_v1(text,timestamptz)",
                "dev_eval.record_photo_dispatch_marker_v1(text,integer,text)",
                "dev_eval.create_photo_job_v2(text,text,text)",
                "dev_eval.transition_photo_job_status_v2(text,text,text,text,text,timestamptz)",
                "dev_eval.claim_photo_job_v2(text,text,timestamptz)",
                "dev_eval.record_photo_dispatch_marker_v2(text,text,integer,text)",
                "dev_eval.record_photo_candidate_batch_v2(text,text,text[],text[],text[],text[])",
                "dev_eval.annotate_photo_candidate_v2(text,text,text,text,boolean)",
                "dev_eval.append_photo_deletion_ledger_v2(text,text,text,text,text)",
                "dev_eval.save_photo_review_draft_v2(text,text,text,text[],text[],text[],boolean[])",
                "dev_eval.discard_photo_review_draft_v2(text,text)",
                "dev_eval.confirm_photo_traits_v2(text,text,text,text[],text[],text[],boolean[],boolean[],text)",
                "dev_eval.list_reconcile_photo_jobs_v2()",
                "dev_eval.list_photo_deletion_ledger_v2(text,text)",
            )
            verify_photo_service_execute_surface(
                connection,
                allowed_procedures=allowed_photo_procedures,
                owner_only_procedures=owner_only_procedures,
            )
            for table in required_relations:
                relation = f"dev_eval.{table}"
                direct = connection.execute(
                    "SELECT has_table_privilege(current_user, %s, 'SELECT'), "
                    "has_table_privilege(current_user, %s, 'INSERT'), "
                    "has_table_privilege(current_user, %s, 'UPDATE'), "
                    "has_table_privilege(current_user, %s, 'DELETE'), "
                    "has_table_privilege(current_user, %s, 'TRUNCATE')",
                    (relation, relation, relation, relation, relation),
                ).fetchone()
                if direct is None or any(bool(value) for value in direct):
                    raise RuntimeError("photo direct table access must not survive 0020")
        self._raise_if_cancelled()
        with psycopg.connect(
            resources.runtime_dsn,
            connect_timeout=DATABASE_CONNECT_TIMEOUT_SECONDS,
            options=DATABASE_SESSION_OPTIONS,
        ) as connection:
            identity = connection.execute("SELECT session_user").fetchone()
            if identity == (PHOTO_AUTHORITY_SERVICE_ROLE,):
                raise RuntimeError("runtime and photo service DSNs must stay separated")
            leaked = connection.execute(
                "SELECT has_function_privilege("
                "current_user, 'dev_eval.create_photo_job_v3(text,text,text)', 'EXECUTE')"
            ).fetchone()
            if leaked != (False,):
                raise RuntimeError("runtime DSN must hold no photo mutation authority")

    def start_api(self, resources: object) -> subprocess.Popen[str]:
        assert isinstance(resources, RuntimeResources)
        if resources.release_authority_environment:
            self._validate_release_authority(resources)
        else:
            _validate_label_freeze_output(resources)
        child_environment = {
            **_safe_environment(self._environment),
            "ITDA_DATABASE_URL": resources.runtime_dsn,
            "ITDA_RUNTIME_ROLE": resources.runtime_name,
            "ITDA_E2E_PHASE3_TEST_SUPPORT": "1",
            "ITDA_PHASE3_LABEL_FREEZE_OUTPUT": str(resources.label_freeze_output),
            "ITDA_LABEL_BUILDER_ROLE": resources.phase3_role_names["builder"],
            "ITDA_PHASE4_PROFILE_RELEASE_AUTHORITY_DATABASE_URL": (
                resources.profile_release_authority_dsn
            ),
            "ITDA_PHOTO_SERVICE_DATABASE_URL": resources.photo_service_dsn,
            "ITDA_PHOTO_QUARANTINE_ROOT": str(resources.photo_quarantine_directory),
            "ITDA_PROFILE_SESSION_DATABASE_URL": resources.profile_session_service_dsn,
            "ITDA_PROFILE_SESSION_KEYRING": (
                f"{PROFILE_SESSION_CURRENT_KID}.{resources.profile_session_current_key},"
                f"{PROFILE_SESSION_PREVIOUS_KID}.{resources.profile_session_previous_key}"
            ),
            "ITDA_PROFILE_SESSION_CURRENT_KID": PROFILE_SESSION_CURRENT_KID,
            "ITDA_CANONICAL_APP_ORIGIN": PROFILE_SESSION_CANONICAL_ORIGIN,
            "ITDA_E2E_ALLOW_INSECURE_COOKIE": "1",
            "ITDA_API_BIND_HOST": API_HOST,
            **{
                f"ITDA_PHASE3_{capability.upper()}_CAPABILITY_SHA256": hashlib.sha256(
                    raw_capability.encode("utf-8")
                ).hexdigest()
                for capability, raw_capability in resources.phase3_capabilities.items()
            },
            **{
                f"ITDA_PHASE3_{capability.upper()}_DATABASE_URL": dsn
                for capability, dsn in resources.phase3_dsns.items()
            },
            **resources.release_authority_environment,
            "PYTHONPATH": str(BACKEND_ROOT / "src"),
        }
        return subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "itda.api.main:app",
                "--host",
                API_HOST,
                "--port",
                str(API_PORT),
                "--no-proxy-headers",
            ],
            cwd=REPOSITORY_ROOT,
            env=child_environment,
            stdout=None,
            stderr=None,
            text=True,
            start_new_session=False,
        )

    def handoff_release_authority(self, resources: RuntimeResources) -> ReleaseAuthorityHandoff:
        receipt, _raw = _read_freeze_receipt(resources)
        payloads, digests, reviewed_records, request = _release_authority_graph(
            receipt,
            suffix=resources.suffix,
            builder_principal=PROFILE_RELEASE_BUILDER_ACTOR_ID,
        )
        active, identity, server_environment, resolution = _publish_release_authority(
            resources,
            payloads,
            digests,
            request,
        )
        resources.release_authority_directory = active
        resources.release_authority_directory_identity = identity
        resources.release_authority_environment = server_environment
        resources.release_reviewed_records = reviewed_records
        resources.release_build_authority_resolution = resolution
        self._validate_release_authority(resources)
        freeze_receipt_sha256 = digests["label_freeze"]
        return ReleaseAuthorityHandoff(
            freeze_receipt_sha256=freeze_receipt_sha256,
            candidate_freeze_receipt_sha256=digests["candidate_freeze_parent"],
            authority_directory=active,
            candidate_manifest_path=active / RELEASE_AUTHORITY_FILES["evidence_candidates"],
            candidate_manifest_sha256=digests["evidence_candidates"],
            server_environment=dict(server_environment),
            public_receipt={
                "freeze_receipt_sha256": freeze_receipt_sha256,
                "candidate_freeze_receipt_sha256": digests["candidate_freeze_parent"],
                "candidate_manifest_sha256": digests["evidence_candidates"],
            },
            reviewed_records=reviewed_records,
        )

    def _validate_release_authority(self, resources: RuntimeResources) -> None:
        from itda.analysis.text.candidate_pipeline import validate_candidate_manifest
        from itda.contracts.profile_release_authority import (
            ProfileReleaseAuthorityPaths,
            ProfileReleaseAuthorityRequest,
            resolve_authoritative_profile_release_candidate,
        )

        directory = resources.release_authority_directory
        identity = resources.release_authority_directory_identity
        if directory is None or identity is None:
            raise RuntimeError("private release authority validation failed")
        parent_descriptor, descriptor = _open_release_authority_descriptors(
            resources,
            operation="validation",
        )
        try:
            if set(os.listdir(descriptor)) != set(RELEASE_AUTHORITY_FILES.values()):
                raise RuntimeError("private release authority validation failed")
            for path_key, digest_key in (
                (
                    "ITDA_PHASE3_CANDIDATE_MANIFEST",
                    "ITDA_PHASE3_CANDIDATE_MANIFEST_SHA256",
                ),
                (
                    "ITDA_E2E_PHASE3_RELEASE_BUILD_INPUT",
                    "ITDA_E2E_PHASE3_RELEASE_BUILD_INPUT_SHA256",
                ),
            ):
                path_value = resources.release_authority_environment.get(path_key)
                digest_value = resources.release_authority_environment.get(digest_key)
                if not path_value or not digest_value or Path(path_value).parent != directory:
                    raise RuntimeError("private release authority validation failed")
                raw = _read_private_regular_file(descriptor, Path(path_value).name)
                if not secrets.compare_digest(_sha256_bytes(raw), digest_value):
                    raise RuntimeError("private release authority validation failed")
            for key in ("LABEL_FREEZE", "CANDIDATE", "REVIEWED", "RIGHTS", "SOURCE"):
                path_key = f"ITDA_PHASE3_PROFILE_RELEASE_{key}_MANIFEST"
                digest_key = f"ITDA_PHASE3_PROFILE_RELEASE_{key}_SHA256"
                path_value = resources.release_authority_environment.get(path_key)
                digest_value = resources.release_authority_environment.get(digest_key)
                if not path_value or not digest_value or Path(path_value).parent != directory:
                    raise RuntimeError("private release authority validation failed")
                raw = _read_private_regular_file(descriptor, Path(path_value).name)
                payload = json.loads(raw)
                field_name = "receipt_sha256" if key == "LABEL_FREEZE" else "manifest_sha256"
                if not isinstance(payload, dict) or not secrets.compare_digest(
                    str(payload.get(field_name)), digest_value
                ):
                    raise RuntimeError("private release authority validation failed")
            candidate_path = resources.release_authority_environment[
                "ITDA_PHASE3_CANDIDATE_MANIFEST"
            ]
            validate_candidate_manifest(
                cast(
                    dict[str, object],
                    json.loads(
                        _read_private_regular_file(
                            descriptor,
                            Path(candidate_path).name,
                            max_bytes=8_000_000,
                        )
                    ),
                )
            )
            build_path = resources.release_authority_environment[
                "ITDA_E2E_PHASE3_RELEASE_BUILD_INPUT"
            ]
            build_input = json.loads(_read_private_regular_file(descriptor, Path(build_path).name))
            if not isinstance(build_input, dict):
                raise RuntimeError("private release authority validation failed")
            authority_request = ProfileReleaseAuthorityRequest(
                release_id=str(build_input["release_id"]),
                builder_principal=resources.phase3_role_names["builder"],
                canonical_lineage_sha256=str(build_input["canonical_lineage_sha256"]),
                dev_lineage_sha256=str(build_input["dev_lineage_sha256"]),
                profile_schema_sha256=str(build_input["profile_schema_sha256"]),
                label_freeze_sha256=str(build_input["label_freeze_sha256"]),
                candidate_manifest_sha256=str(build_input["candidate_run_sha256"]),
                reviewed_manifest_sha256=str(build_input["reviewed_manifest_sha256"]),
                rights_manifest_sha256=str(build_input["rights_manifest_sha256"]),
                source_manifest_sha256=str(build_input["source_manifest_sha256"]),
            )
            resolve_authoritative_profile_release_candidate(
                request=authority_request,
                paths=ProfileReleaseAuthorityPaths(
                    label_freeze=Path(
                        resources.release_authority_environment[
                            "ITDA_PHASE3_PROFILE_RELEASE_LABEL_FREEZE_MANIFEST"
                        ]
                    ),
                    candidate_manifest=Path(
                        resources.release_authority_environment[
                            "ITDA_PHASE3_PROFILE_RELEASE_CANDIDATE_MANIFEST"
                        ]
                    ),
                    reviewed_manifest=Path(
                        resources.release_authority_environment[
                            "ITDA_PHASE3_PROFILE_RELEASE_REVIEWED_MANIFEST"
                        ]
                    ),
                    rights_manifest=Path(
                        resources.release_authority_environment[
                            "ITDA_PHASE3_PROFILE_RELEASE_RIGHTS_MANIFEST"
                        ]
                    ),
                    source_manifest=Path(
                        resources.release_authority_environment[
                            "ITDA_PHASE3_PROFILE_RELEASE_SOURCE_MANIFEST"
                        ]
                    ),
                ),
            )
            _verify_release_authority_descriptor_identity(
                parent_descriptor,
                descriptor,
                identity,
                operation="validation",
            )
        except (KeyError, OSError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeError("private release authority validation failed") from error
        finally:
            os.close(descriptor)
            os.close(parent_descriptor)

    def _seed_release_reviewed_records(self, resources: RuntimeResources) -> None:
        import psycopg

        with psycopg.connect(
            resources.phase3_dsns["builder"],
            connect_timeout=DATABASE_CONNECT_TIMEOUT_SECONDS,
            options=DATABASE_SESSION_OPTIONS,
        ) as connection:
            for record in resources.release_reviewed_records:
                connection.execute(
                    "INSERT INTO dev_eval.evidence_candidate_manifests ("
                    "candidate_manifest_sha256, payload, registered_by) VALUES ("
                    "%s, %s::jsonb, session_user) "
                    "ON CONFLICT ON CONSTRAINT pk_phase3_candidate_manifests DO NOTHING",
                    (
                        record["candidate_manifest_sha256"],
                        json.dumps(
                            {
                                "schema_version": (
                                    "itda.profile-release-member-candidate-reference.v1"
                                ),
                                "candidate_manifest_sha256": record["candidate_manifest_sha256"],
                            },
                            sort_keys=True,
                        ),
                    ),
                )
                connection.execute(
                    "INSERT INTO dev_eval.reviewed_evidence_manifests ("
                    "manifest_sha256, candidate_manifest_sha256, accepted_review_set_sha256, "
                    "payload, created_by, created_at) VALUES ("
                    "%s, %s, %s, %s::jsonb, session_user, %s) "
                    "ON CONFLICT ON CONSTRAINT pk_phase3_reviewed_manifests DO NOTHING",
                    (
                        record["manifest_sha256"],
                        record["candidate_manifest_sha256"],
                        record["accepted_review_set_sha256"],
                        json.dumps(record, ensure_ascii=False, sort_keys=True),
                        record["finalized_at"],
                    ),
                )
            connection.commit()

    def _register_release_build_authority(self, resources: RuntimeResources) -> None:
        import psycopg
        from psycopg.types.json import Jsonb

        from itda.contracts.profile_release_authority import (
            ProfileReleaseBuildAuthorityResolution,
        )

        resolution = resources.release_build_authority_resolution
        if not isinstance(resolution, ProfileReleaseBuildAuthorityResolution):
            raise RuntimeError("private release build authority is unavailable")
        with psycopg.connect(
            resources.admin_dsn,
            autocommit=True,
            connect_timeout=DATABASE_CONNECT_TIMEOUT_SECONDS,
            options=DATABASE_SESSION_OPTIONS,
        ) as connection:
            connection.execute(
                "INSERT INTO dev_eval.profile_release_fixed_root_authorities_v1 ("
                "authority_registry_id, candidate_payload, candidate_sha256, "
                "authority_root_sha256, builder_database_principal, "
                "expected_predecessor_sha256, "
                "expected_predecessor_lifecycle_receipt_sha256, resolution_sha256) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                (
                    str(resolution.authority_registry_id),
                    Jsonb(resolution.candidate.model_dump(mode="json")),
                    resolution.candidate_sha256,
                    resolution.authority_root_sha256,
                    resolution.builder_database_principal,
                    resolution.expected_predecessor_sha256,
                    resolution.expected_predecessor_lifecycle_receipt_sha256,
                    resolution.resolution_sha256,
                ),
            )
            stored = connection.execute(
                "SELECT candidate_sha256, authority_root_sha256, "
                "builder_database_principal, expected_predecessor_sha256, "
                "expected_predecessor_lifecycle_receipt_sha256, resolution_sha256 "
                "FROM dev_eval.profile_release_fixed_root_authorities_v1 "
                "WHERE authority_registry_id = %s",
                (str(resolution.authority_registry_id),),
            ).fetchone()
        expected = (
            resolution.candidate_sha256,
            resolution.authority_root_sha256,
            resolution.builder_database_principal,
            resolution.expected_predecessor_sha256,
            resolution.expected_predecessor_lifecycle_receipt_sha256,
            resolution.resolution_sha256,
        )
        if stored != expected:
            raise RuntimeError("private release build authority registration failed")

    def wait_ready(self, resources: object, api_process: object) -> None:
        assert isinstance(resources, RuntimeResources)
        assert isinstance(api_process, subprocess.Popen)
        deadline = self._clock() + API_READY_TIMEOUT_SECONDS
        questionnaire_path = REPOSITORY_ROOT / "contracts" / "questionnaire-v2.json"
        expected_title = json.loads(questionnaire_path.read_text(encoding="utf-8"))["questions"][0][
            "title_ko"
        ]
        last_error: Exception | None = None
        while self._clock() < deadline:
            self._raise_if_cancelled()
            returncode = api_process.poll()
            if returncode is not None:
                raise RuntimeError(f"Uvicorn exited before readiness with code {returncode}")
            try:
                request = urllib.request.Request(
                    API_READY_URL,
                    headers={"Accept": "application/json"},
                )
                with urllib.request.urlopen(request, timeout=2.0) as response:
                    content_type = response.headers.get_content_type()
                    payload = json.loads(response.read())
                    if (
                        response.status == 200
                        and content_type == "application/json"
                        and payload["questions"][0]["title_ko"] == expected_title
                    ):
                        return
            except (
                KeyError,
                json.JSONDecodeError,
                OSError,
                urllib.error.URLError,
            ) as error:
                last_error = error
            self._sleep(STARTUP_POLL_SECONDS)
        raise TimeoutError(
            f"FastAPI questionnaire JSON did not become ready within "
            f"{API_READY_TIMEOUT_SECONDS:.0f} seconds"
        ) from last_error

    def wait_until_stopped(
        self, resources: object, api_process: object, stop_requested: object
    ) -> object:
        assert isinstance(resources, RuntimeResources)
        assert isinstance(api_process, subprocess.Popen)
        assert isinstance(stop_requested, threading.Event)
        current_process = api_process
        handoff_complete = False
        while not stop_requested.wait(0.25):
            returncode = current_process.poll()
            if returncode is not None:
                raise RuntimeError(f"Uvicorn exited unexpectedly with code {returncode}")
            if not handoff_complete and resources.label_freeze_output.exists():
                self.handoff_release_authority(resources)
                self._seed_release_reviewed_records(resources)
                self._register_release_build_authority(resources)
                self.stop_api(current_process)
                current_process = self.start_api(resources)
                try:
                    self.wait_ready(resources, current_process)
                except BaseException:
                    self.stop_api(current_process)
                    raise
                handoff_complete = True
        return current_process

    def stop_api(self, api_process: object) -> None:
        assert isinstance(api_process, subprocess.Popen)
        if api_process.poll() is not None:
            return
        api_process.terminate()
        try:
            api_process.wait(timeout=self._cleanup_timeout(15.0))
        except subprocess.TimeoutExpired:
            api_process.kill()
            api_process.wait(timeout=self._cleanup_timeout(5.0))

    def cleanup_private_output(self, resources: object) -> None:
        assert isinstance(resources, RuntimeResources)
        _cleanup_release_authority(resources)
        _cleanup_private_label_freeze_output(
            resources.label_freeze_directory,
            resources.label_freeze_output,
            resources.label_freeze_directory_identity,
        )
        _cleanup_private_photo_quarantine_directory(
            resources.photo_quarantine_directory,
            resources.photo_quarantine_directory_identity,
        )

    def drop_database_and_role(self, resources: object) -> None:
        import psycopg
        from psycopg import sql

        assert isinstance(resources, RuntimeResources)
        connect_budget = self._database_cleanup_timeout(float(DATABASE_CONNECT_TIMEOUT_SECONDS))
        if connect_budget < 1:
            raise TimeoutError(
                "less than one second remains for database cleanup connection "
                "after reserving Compose down"
            )
        with psycopg.connect(
            resources.admin_postgres_dsn,
            autocommit=True,
            connect_timeout=max(1, int(connect_budget)),
            options=DATABASE_SESSION_OPTIONS,
        ) as connection:
            statements: list[tuple[str | sql.Composed, tuple[str, ...] | None]] = [
                (
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = %s AND pid <> pg_backend_pid()",
                    (resources.database_name,),
                ),
                (
                    sql.SQL("DROP DATABASE IF EXISTS {}").format(
                        sql.Identifier(resources.database_name)
                    ),
                    None,
                ),
                (
                    sql.SQL("DROP ROLE IF EXISTS {}").format(
                        sql.Identifier(resources.runtime_name)
                    ),
                    None,
                ),
            ]
            statements.extend(
                (
                    sql.SQL("DROP ROLE IF EXISTS {}").format(
                        sql.Identifier(resources.phase3_role_names[capability])
                    ),
                    None,
                )
                for capability in reversed(PHASE3_CAPABILITIES)
            )
            statements.extend(
                [
                    (
                        sql.SQL("DROP ROLE IF EXISTS {}").format(
                            sql.Identifier(PROFILE_RELEASE_AUTHORITY_SERVICE_ROLE)
                        ),
                        None,
                    ),
                    (
                        sql.SQL("DROP ROLE IF EXISTS {}").format(
                            sql.Identifier(PROFILE_RELEASE_WRITE_AUTHORITY_ROLE)
                        ),
                        None,
                    ),
                    (
                        sql.SQL("DROP ROLE IF EXISTS {}").format(
                            sql.Identifier(PHOTO_AUTHORITY_SERVICE_ROLE)
                        ),
                        None,
                    ),
                    (
                        sql.SQL("DROP ROLE IF EXISTS {}").format(
                            sql.Identifier(PHOTO_WRITE_AUTHORITY_ROLE)
                        ),
                        None,
                    ),
                    (
                        sql.SQL("DROP ROLE IF EXISTS {}").format(
                            sql.Identifier(PROFILE_SESSION_SERVICE_ROLE)
                        ),
                        None,
                    ),
                    (
                        sql.SQL("DROP ROLE IF EXISTS {}").format(
                            sql.Identifier(PROFILE_SESSION_OWNER_ROLE)
                        ),
                        None,
                    ),
                ]
            )
            for statement, parameters in statements:
                statement_budget = self._database_cleanup_timeout(
                    DATABASE_STATEMENT_TIMEOUT_MS / 1_000
                )
                timeout_ms = max(1, int(statement_budget * 1_000))
                connection.execute(
                    "SELECT set_config('statement_timeout', %s, false)",
                    (str(timeout_ms),),
                )
                connection.execute(statement, parameters)

    def compose_down(self, resources: object) -> None:
        assert isinstance(resources, RuntimeResources)
        self._compose(
            resources,
            ["down", "--volumes", "--remove-orphans", "--timeout", "5"],
            timeout=self._cleanup_timeout(COMPOSE_DOWN_RESERVED_SECONDS),
        )


_SignalHandler = Callable[[int, FrameType | None], Any] | int | None


def _install_signal_handlers(
    stop_requested: threading.Event,
) -> dict[int, _SignalHandler]:
    previous: dict[int, _SignalHandler] = {}

    def request_stop(_signum: int, _frame: FrameType | None) -> None:
        stop_requested.set()

    if threading.current_thread() is not threading.main_thread():
        return previous
    for signum in (signal.SIGINT, signal.SIGTERM):
        previous[signum] = signal.getsignal(signum)
        signal.signal(signum, request_stop)
    return previous


def _restore_signal_handlers(previous: Mapping[int, _SignalHandler]) -> None:
    for signum, handler in previous.items():
        signal.signal(signum, handler)


def run_supervisor(
    *,
    environment: Mapping[str, str],
    lifecycle: RuntimeLifecycle | None = None,
    preflight_check: Callable[..., object] = preflight,
) -> None:
    """Run until signalled, then unwind Uvicorn, database state, and Compose."""

    preflight_check(environment=environment)
    active_lifecycle = lifecycle or DefaultRuntimeLifecycle(environment)
    resources: object | None = None
    api_process: object | None = None
    compose_attempted = False
    database_started = False
    primary_error: BaseException | None = None
    stop_requested = threading.Event()
    previous_handlers = _install_signal_handlers(stop_requested)
    set_stop_event = getattr(active_lifecycle, "set_stop_event", None)
    if callable(set_stop_event):
        set_stop_event(stop_requested)
    try:
        resources = active_lifecycle.allocate()
        if stop_requested.is_set():
            raise StartupCancelled("E2E startup interrupted before Compose")
        compose_attempted = True
        active_lifecycle.compose_up(resources)
        if stop_requested.is_set():
            raise StartupCancelled("E2E startup interrupted before migration")
        database_started = True
        active_lifecycle.migrate(resources)
        if stop_requested.is_set():
            raise StartupCancelled("E2E startup interrupted after migration")
        active_lifecycle.verify_runtime_role(resources)
        if stop_requested.is_set():
            raise StartupCancelled("E2E startup interrupted before API start")
        api_process = active_lifecycle.start_api(resources)
        active_lifecycle.wait_ready(resources, api_process)
        replacement_process = active_lifecycle.wait_until_stopped(
            resources, api_process, stop_requested
        )
        if replacement_process is not None:
            api_process = replacement_process
    except BaseException as error:
        primary_error = error
    finally:
        cleanup_errors: list[BaseException] = []
        begin_cleanup = getattr(active_lifecycle, "begin_cleanup", None)
        if callable(begin_cleanup):
            begin_cleanup()
        if api_process is not None:
            try:
                active_lifecycle.stop_api(api_process)
            except BaseException as error:
                cleanup_errors.append(error)
        if resources is not None:
            try:
                active_lifecycle.cleanup_private_output(resources)
            except BaseException as error:
                cleanup_errors.append(error)
        if resources is not None and database_started:
            try:
                active_lifecycle.drop_database_and_role(resources)
            except BaseException as error:
                cleanup_errors.append(error)
        if resources is not None and compose_attempted:
            try:
                active_lifecycle.compose_down(resources)
            except BaseException as error:
                cleanup_errors.append(error)
        _restore_signal_handlers(previous_handlers)
        if primary_error is not None:
            if cleanup_errors:
                primary_error.add_note(
                    "cleanup also failed: " + "; ".join(str(error) for error in cleanup_errors)
                )
            raise primary_error
        if cleanup_errors:
            raise RuntimeError(
                "E2E cleanup failed: " + "; ".join(str(error) for error in cleanup_errors)
            )


def _lifecycle_playwright_command() -> list[str]:
    return [
        "mise",
        "exec",
        "--",
        "pnpm",
        "--dir",
        "web",
        "exec",
        "playwright",
        "test",
        "e2e/runtime-lifecycle.spec.ts",
        "--project=chromium",
        "--workers=1",
    ]


def _docker_json_rows(
    command: Sequence[str], *, environment: Mapping[str, str]
) -> list[dict[str, object]]:
    completed = subprocess.run(
        list(command),
        cwd=REPOSITORY_ROOT,
        env=dict(environment),
        capture_output=True,
        check=False,
        text=True,
        timeout=15,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"residue inspection failed: {' '.join(command)}")
    raw = completed.stdout.strip()
    if not raw:
        return []
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        try:
            return [row for line in raw.splitlines() if isinstance((row := json.loads(line)), dict)]
        except json.JSONDecodeError as error:
            raise RuntimeError(
                f"residue inspection returned invalid JSON: {' '.join(command)}"
            ) from error
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        return [payload]
    raise RuntimeError(f"residue inspection returned unexpected JSON: {' '.join(command)}")


@dataclass(frozen=True)
class _ProcessTableRow:
    pid: int
    process_group_id: int
    command: str


def _process_table_rows() -> tuple[_ProcessTableRow, ...]:
    completed = subprocess.run(
        ["ps", "e", "-ax", "-o", "pid=,pgid=,command="],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )
    if completed.returncode != 0:
        raise RuntimeError("could not inspect lifecycle process table")
    rows: list[_ProcessTableRow] = []
    for line in completed.stdout.splitlines():
        fields = line.strip().split(maxsplit=2)
        if len(fields) != 3:
            continue
        try:
            pid, process_group_id = (int(field) for field in fields[:2])
        except ValueError:
            continue
        rows.append(
            _ProcessTableRow(
                pid=pid,
                process_group_id=process_group_id,
                command=fields[2],
            )
        )
    return tuple(rows)


def _command_has_exact_run_id(command: str, run_id: str) -> bool:
    return f"ITDA_E2E_RUN_ID={run_id}" in command.split()


def _command_has_token_sequence(
    command: str,
    expected_tokens: Sequence[str],
) -> bool:
    command_tokens = command.split()
    sequence_length = len(expected_tokens)
    return any(
        command_tokens[index : index + sequence_length] == list(expected_tokens)
        for index in range(len(command_tokens) - sequence_length + 1)
    )


def assert_no_runtime_residue(run_id: str, *, environment: Mapping[str, str]) -> None:
    safe_environment = _safe_environment(environment)
    expected_docker_prefix = f"itda_e2e_{_identifier_fragment(run_id)}_"
    process_tokens = ("playwright test", "itda.cli.e2e_runtime", "uvicorn", "next")
    leaked_processes = [
        row.command
        for row in _process_table_rows()
        if _command_has_exact_run_id(row.command, run_id)
        and any(token in row.command for token in process_tokens)
    ]
    compose_rows = _docker_json_rows(
        ["docker", "compose", "ls", "--all", "--format", "json"],
        environment=safe_environment,
    )
    container_rows = _docker_json_rows(
        [
            "docker",
            "ps",
            "--all",
            "--format",
            ('{"name":{{json .Names}},"project":{{json (.Label "com.docker.compose.project")}}}'),
        ],
        environment=safe_environment,
    )
    volume_rows = _docker_json_rows(
        [
            "docker",
            "volume",
            "ls",
            "--format",
            ('{"name":{{json .Name}},"project":{{json (.Label "com.docker.compose.project")}}}'),
        ],
        environment=safe_environment,
    )
    network_rows = _docker_json_rows(
        [
            "docker",
            "network",
            "ls",
            "--format",
            ('{"name":{{json .Name}},"project":{{json (.Label "com.docker.compose.project")}}}'),
        ],
        environment=safe_environment,
    )

    def belongs_to_run(row: Mapping[str, object]) -> bool:
        return any(
            str(row.get(key, "")).startswith(expected_docker_prefix)
            for key in ("Name", "name", "project")
        )

    leaked_compose = [row for row in compose_rows if belongs_to_run(row)]
    leaked_containers = [row for row in container_rows if belongs_to_run(row)]
    leaked_volumes = [row for row in volume_rows if belongs_to_run(row)]
    leaked_networks = [row for row in network_rows if belongs_to_run(row)]
    if leaked_processes or leaked_compose or leaked_containers or leaked_volumes or leaked_networks:
        raise RuntimeError(
            "lifecycle residue detected "
            f"(processes={len(leaked_processes)}, compose={len(leaked_compose)}, "
            f"containers={len(leaked_containers)}, volumes={len(leaked_volumes)}, "
            f"networks={len(leaked_networks)})"
        )


def _validate_completed_lifecycle(
    *,
    mode: str,
    returncode: int,
    intentional_failure_marker_seen: bool,
    output: str,
) -> None:
    if mode == "success" and returncode != 0:
        raise RuntimeError("success lifecycle mode failed:\n" + output)
    if mode != "intentional-failure":
        return
    if returncode == 0:
        raise RuntimeError("intentional-failure lifecycle mode unexpectedly passed")
    if not intentional_failure_marker_seen:
        raise RuntimeError(
            "intentional-failure lifecycle exited nonzero before marker "
            f"{LIFECYCLE_INTENTIONAL_FAILURE_MARKER}"
        )


def _lifecycle_output_payload(
    line: str,
    *,
    web_server_names: Sequence[str] = PLAYWRIGHT_WEB_SERVER_NAMES,
) -> str:
    payload = _ANSI_ESCAPE_SEQUENCE.sub("", line)
    payload = payload.removesuffix("\n").removesuffix("\r")
    for name in web_server_names:
        prefix = f"[{name}] "
        if payload.startswith(prefix):
            return payload.removeprefix(prefix)
    return payload


def _matches_lifecycle_marker(
    line: str,
    expected_marker: str,
    *,
    web_server_names: Sequence[str] = PLAYWRIGHT_WEB_SERVER_NAMES,
) -> bool:
    return _lifecycle_output_payload(line, web_server_names=web_server_names) == expected_marker


def _interruption_sentinel_timeout(interrupt_phase: str | None) -> float:
    if interrupt_phase is None:
        return LIFECYCLE_MODE_TIMEOUT_SECONDS
    if interrupt_phase == "compose-readiness":
        return (
            PREFLIGHT_TIMEOUT_SECONDS
            + COMPOSE_UP_TIMEOUT_SECONDS
            + COMPOSE_ACTIVE_PROBE_TIMEOUT_SECONDS
        )
    return PREFLIGHT_TIMEOUT_SECONDS + sum(BACKEND_SEQUENTIAL_STARTUP_BUDGETS[:3])


def _process_group_pids(process_group_id: int) -> tuple[int, ...]:
    completed = subprocess.run(
        ["ps", "-axo", "pid=,pgid=,state="],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )
    if completed.returncode != 0:
        raise RuntimeError("could not inspect lifecycle process group")
    pids: list[int] = []
    for line in completed.stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        fields = stripped.split()
        if len(fields) != 3:
            raise RuntimeError("could not parse lifecycle process group")
        try:
            pid, pgid = (int(field) for field in fields[:2])
        except ValueError as error:
            raise RuntimeError("could not parse lifecycle process group") from error
        state = fields[2]
        if pgid == process_group_id and not state.startswith("Z"):
            pids.append(pid)
    return tuple(pids)


def _terminate_process_group_id(
    process_group_id: int,
    *,
    graceful_signal: signal.Signals = signal.SIGTERM,
    grace_seconds: float = 60.0,
    kill_grace_seconds: float = 5.0,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    """Terminate every member of an owned process group and report escalation."""

    if not _process_group_pids(process_group_id):
        return False
    try:
        os.killpg(process_group_id, graceful_signal)
    except ProcessLookupError:
        return False
    deadline = clock() + grace_seconds
    while True:
        if not _process_group_pids(process_group_id):
            return False
        if clock() >= deadline:
            break
        sleep(STARTUP_POLL_SECONDS)

    try:
        os.killpg(process_group_id, signal.SIGKILL)
    except ProcessLookupError:
        return True
    kill_deadline = clock() + kill_grace_seconds
    while True:
        if not _process_group_pids(process_group_id):
            return True
        if clock() >= kill_deadline:
            raise TimeoutError(f"lifecycle process group {process_group_id} survived SIGKILL")
        sleep(STARTUP_POLL_SECONDS)


def _terminate_process_group(
    process: subprocess.Popen[str],
    *,
    graceful_signal: signal.Signals = signal.SIGTERM,
    grace_seconds: float = 60.0,
    kill_grace_seconds: float = 5.0,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    process.poll()
    return _terminate_process_group_id(
        process.pid,
        graceful_signal=graceful_signal,
        grace_seconds=grace_seconds,
        kill_grace_seconds=kill_grace_seconds,
        clock=clock,
        sleep=sleep,
    )


def _run_owned_process_group_id(
    run_id: str,
    *,
    outer_process_group_id: int,
    group_name: str,
    command_tokens: Sequence[str],
) -> int:
    rows = _process_table_rows()
    owned_command_rows = tuple(
        row
        for row in rows
        if _command_has_exact_run_id(row.command, run_id)
        and _command_has_token_sequence(row.command, command_tokens)
    )
    candidate_group_ids = {row.process_group_id for row in owned_command_rows}
    if len(candidate_group_ids) != 1:
        raise RuntimeError(
            f"could not identify exactly one exact run-owned {group_name} process group "
            f"(found={len(candidate_group_ids)})"
        )
    process_group_id = next(iter(candidate_group_ids))
    if process_group_id <= 1 or process_group_id in {
        os.getpgrp(),
        outer_process_group_id,
    }:
        raise RuntimeError(f"refusing excluded {group_name} process group {process_group_id}")
    group_members = tuple(row for row in rows if row.process_group_id == process_group_id)
    if not group_members or any(
        not _command_has_exact_run_id(row.command, run_id) for row in group_members
    ):
        raise RuntimeError(
            f"refusing {group_name} process group {process_group_id} with mixed ownership"
        )
    return process_group_id


def _run_owned_backend_process_group_id(
    run_id: str,
    *,
    outer_process_group_id: int,
) -> int:
    return _run_owned_process_group_id(
        run_id,
        outer_process_group_id=outer_process_group_id,
        group_name="backend",
        command_tokens=("itda.cli.e2e_runtime",),
    )


def _run_owned_frontend_process_group_id(
    run_id: str,
    *,
    outer_process_group_id: int,
) -> int:
    return _run_owned_process_group_id(
        run_id,
        outer_process_group_id=outer_process_group_id,
        group_name="frontend",
        command_tokens=FRONTEND_PROCESS_COMMAND,
    )


def _run_lifecycle_mode(
    *,
    mode: str,
    run_id: str,
    environment: Mapping[str, str],
    interrupt_phase: str | None = None,
) -> None:
    child_environment = {
        **_safe_environment(environment),
        "ITDA_E2E_LIFECYCLE_MODE": mode,
        "ITDA_E2E_RUN_ID": run_id,
    }
    sentinel: str | None = None
    if mode == "wait-for-interruption":
        try:
            sentinel = LIFECYCLE_INTERRUPT_SENTINELS[interrupt_phase]
        except KeyError as error:
            raise ValueError(f"unknown lifecycle interruption phase: {interrupt_phase}") from error
        if interrupt_phase is not None:
            child_environment["ITDA_E2E_INTERRUPT_PHASE"] = interrupt_phase
    process = subprocess.Popen(
        _lifecycle_playwright_command(),
        cwd=REPOSITORY_ROOT,
        env=child_environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    output_lines: list[str] = []
    sentinel_seen = threading.Event()
    intentional_failure_marker_seen = threading.Event()

    def consume_output() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            output_lines.append(line)
            if sentinel is not None and _matches_lifecycle_marker(line, sentinel):
                sentinel_seen.set()
            if _matches_lifecycle_marker(
                line,
                LIFECYCLE_INTENTIONAL_FAILURE_MARKER,
            ):
                intentional_failure_marker_seen.set()

    reader = threading.Thread(target=consume_output, daemon=True)
    reader.start()
    try:
        if sentinel is None:
            returncode = process.wait(timeout=LIFECYCLE_MODE_TIMEOUT_SECONDS)
            reader.join(timeout=5)
            _validate_completed_lifecycle(
                mode=mode,
                returncode=returncode,
                intentional_failure_marker_seen=intentional_failure_marker_seen.is_set(),
                output="".join(output_lines),
            )
        else:
            interruption_name = interrupt_phase or "ready-state"
            sentinel_timeout = _interruption_sentinel_timeout(interrupt_phase)
            sentinel_deadline = time.monotonic() + sentinel_timeout
            while not sentinel_seen.wait(STARTUP_POLL_SECONDS):
                polled_returncode = process.poll()
                if polled_returncode is not None:
                    raise RuntimeError(
                        f"{interruption_name} lifecycle exited with code {polled_returncode} "
                        f"before sentinel {sentinel}"
                    )
                if time.monotonic() >= sentinel_deadline:
                    raise TimeoutError(
                        f"interruption sentinel {sentinel} was not observed for {interruption_name}"
                    )
            backend_process_group_id = _run_owned_backend_process_group_id(
                run_id,
                outer_process_group_id=process.pid,
            )
            frontend_process_group_id: int | None = None
            if interrupt_phase is None:
                frontend_process_group_id = _run_owned_frontend_process_group_id(
                    run_id,
                    outer_process_group_id=process.pid,
                )
            backend_escalated = _terminate_process_group_id(
                backend_process_group_id,
                graceful_signal=signal.SIGTERM,
            )
            if backend_escalated:
                raise TimeoutError(
                    f"{interruption_name} interruption exceeded the backend's 60-second grace"
                )
            if frontend_process_group_id is not None:
                frontend_escalated = _terminate_process_group_id(
                    frontend_process_group_id,
                    graceful_signal=signal.SIGTERM,
                    grace_seconds=FRONTEND_SHUTDOWN_GRACE_SECONDS,
                )
                if frontend_escalated:
                    raise TimeoutError(
                        f"{interruption_name} interruption exceeded the frontend's "
                        f"{FRONTEND_SHUTDOWN_GRACE_SECONDS:.0f}-second grace"
                    )
            escalated = _terminate_process_group(
                process,
                graceful_signal=signal.SIGINT,
            )
            if escalated:
                raise TimeoutError(
                    f"{interruption_name} interruption exceeded Playwright's 60-second grace"
                )
            if process.returncode == 0:
                raise RuntimeError(f"{interruption_name} interruption unexpectedly passed")
    finally:
        if _process_group_pids(process.pid):
            _terminate_process_group(
                process,
                graceful_signal=signal.SIGINT,
            )
        process.wait()
        reader.join()
        assert_no_runtime_residue(run_id, environment=environment)


def run_lifecycle_gate(*, environment: Mapping[str, str]) -> None:
    """Run success, failure, startup interruption, and ready interruption modes."""

    _require_offline_boundary(environment)
    unique = f"{os.getpid()}_{uuid.uuid4().hex[:8]}"
    _run_lifecycle_mode(
        mode="success",
        run_id=f"success_{unique}",
        environment=environment,
    )
    _run_lifecycle_mode(
        mode="intentional-failure",
        run_id=f"failure_{unique}",
        environment=environment,
    )
    for phase in ("compose-readiness", "migration"):
        _run_lifecycle_mode(
            mode="wait-for-interruption",
            run_id=f"interrupt_{phase.replace('-', '_')}_{unique}",
            environment=environment,
            interrupt_phase=phase,
        )
    _run_lifecycle_mode(
        mode="wait-for-interruption",
        run_id=f"interrupt_ready_{unique}",
        environment=environment,
        interrupt_phase=None,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="validate immutable local prerequisites and exit",
    )
    parser.add_argument(
        "--lifecycle-gate",
        action="store_true",
        help="run all black-box lifecycle modes and residue assertions",
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    environment: Mapping[str, str] | None = None,
) -> int:
    args = _parser().parse_args(argv)
    active_environment = dict(os.environ if environment is None else environment)
    try:
        if args.preflight_only:
            preflight(environment=active_environment)
        elif args.lifecycle_gate:
            run_lifecycle_gate(environment=active_environment)
        else:
            run_supervisor(environment=active_environment)
    except (PreflightError, RuntimeError, TimeoutError) as error:
        print(f"e2e-runtime: {redact_diagnostic(str(error), ())}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
