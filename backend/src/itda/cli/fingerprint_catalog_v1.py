"""Build and verify the immutable Phase 2 v1/catalog-history boundary."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import secrets
import stat
import subprocess
from collections.abc import Iterable
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path, PurePosixPath
from typing import Any

from itda.domain.canonical import canonical_json_bytes, canonical_sha256

SCHEMA_VERSION = "v1-immutability-manifest-v1"
SUCCESSOR_SCHEMA_VERSION = "v1-immutability-manifest-successor-v2"
PROTECTED_MANIFEST_SCHEMA_VERSION = "phase2-gap-closure-protected-manifest-v1"
CATALOG_ROOT = "artifacts/restricted/catalog/v1"
PHASE_ROOT = ".planning/phases/02-canonical-36-rights-and-evaluation-manifest"
COMPLETED_PLAN_IDS = tuple(f"02-{ordinal:02d}" for ordinal in range(1, 9))
SUCCESSOR_TARGET = "artifacts/restricted/catalog/v2/lineage/v1-immutability-manifest-v2.json"
PREDECESSOR_TARGET = "artifacts/restricted/catalog/v2/lineage/v1-immutability-manifest.json"
EXPECTED_RECORDED_INVENTORY_SHA256 = (
    "ac09f3a884b4b2e2c8b51d875346bb46ece5b3fc138973e38d6d7dad3fd91483"
)
EXPECTED_CURRENT_INVENTORY_SHA256 = (
    "e7011e47b22a6e0886ce8cd6e95e4c52f2448153e4fb94cccaacab204d039a32"
)
DELTA_OWNER_COMMITS: dict[str, tuple[str, str]] = {
    "backend/src/itda/cli/approve_catalog.py": (
        "02-21",
        "93717eb",
    ),
    "backend/src/itda/contracts/catalog_manifest.py": (
        "02-25",
        "3a4703a",
    ),
    "backend/src/itda/contracts/catalog_release.py": (
        "02-21",
        "d276d3b",
    ),
    "backend/tests/pipeline/test_catalog_relationships.py": (
        "02-25",
        "b1a3e5e",
    ),
}
EXPECTED_DELTA_PATHS = tuple(sorted(DELTA_OWNER_COMMITS, key=str.encode))
SUCCESSOR_KEYS = tuple(
    sorted(
        {
            "schema_version",
            "predecessor",
            "catalog_v1_tree_sha256",
            "planning_history_tree_sha256",
            "recorded_inventory_sha256",
            "current_inventory_sha256",
            "tracked_source_delta",
            "exceptional_delta_allowlist",
            "migration_reason",
            "successor_sha256",
        }
    )
)
PROTECTED_MANIFEST_KEYS = tuple(
    sorted(
        {
            "schema_version",
            "plan_id",
            "stage",
            "owner_count",
            "owners",
            "required_absences",
            "identity_rows_sha256",
            "protected_set_sha256",
            "protected_manifest_sha256",
        }
    )
)

PROTECTED_COMPLETED_PLAN_IDS = (
    "02-01",
    "02-02",
    "02-03",
    "02-04",
    "02-05",
    "02-06",
    "02-07",
    "02-08",
    "02-09",
    "02-10",
    "02-11",
    "02-12",
    "02-13",
    "02-14",
    "02-15",
    "02-16",
    "02-17",
    "02-18",
    "02-20",
    "02-21",
    "02-22",
    "02-23",
    "02-24",
    "02-25",
    "02-26",
    "02-27",
    "02-28",
    "02-33",
    "02-34",
    "02-35",
    "02-36",
    "02-37",
    "02-41",
    "02-47",
    "02-48",
    "02-51",
    "02-52",
    "02-53",
    "02-54",
    "02-55",
    "02-56",
    "02-57",
    "02-58",
    "02-59",
)
PROTECTED_HISTORY_FILES = (
    "02-19-SUPERSEDED.md",
    "02-29-POSTGRESQL-HISTORY.md",
    "02-29-SUPERSEDED.md",
    "02-30-POSTGRESQL-HISTORY.md",
    "02-30-SUPERSEDED.md",
    "02-31-POSTGRESQL-HISTORY.md",
    "02-31-SUPERSEDED.md",
    "02-32-POSTGRESQL-HISTORY.md",
    "02-32-SUPERSEDED.md",
    "02-38-FAILURE-ATTESTATION.md",
    "02-38-FAILURE-RECORD.md",
    "02-39-SUPERSEDED.md",
    "02-40-SUPERSEDED.md",
    "02-42-SUPERSEDED.md",
    "02-43-SUPERSEDED.md",
    "02-44-SUPERSEDED.md",
    "02-45-SUPERSEDED.md",
    "02-46-SUPERSEDED.md",
    "02-49-FAILURE-RECORD.md",
    "02-49-TERMINAL-HISTORY.md",
    "02-50-SUPERSEDED.md",
)
PROTECTED_REQUIRED_ABSENCES = tuple(
    f"{PHASE_ROOT}/{plan_id}-SUMMARY.md"
    for plan_id in (
        "02-19",
        "02-29",
        "02-30",
        "02-31",
        "02-32",
        "02-38",
        "02-39",
        "02-40",
        "02-42",
        "02-43",
        "02-44",
        "02-45",
        "02-46",
        "02-49",
        "02-50",
    )
)
PROTECTED_FIXED_FILES = (
    "artifacts/restricted/catalog/v2/lineage/v1-immutability-manifest.json",
    "artifacts/restricted/catalog/v2/lineage/historical-verification-equivalence.json",
    "artifacts/restricted/catalog/v2/lineage/historical-verification-evidence.json",
    "artifacts/restricted/catalog/v2/rights/rights-projection.json",
    "artifacts/restricted/catalog/v2/audit/candidate-objective-evidence.json",
    *EXPECTED_DELTA_PATHS,
    "backend/src/itda/contracts/catalog_activation.py",
    "backend/src/itda/contracts/authority.py",
    "backend/src/itda/cli/activate_catalog.py",
    "backend/tests/security/test_catalog_activation.py",
    "artifacts/restricted/catalog/v2/activation/catalog-activation-request.json",
    "artifacts/restricted/catalog/v2/activation/catalog-activation-state-attestation.json",
    "artifacts/restricted/catalog/v2/activation/catalog-activation-event.json",
    "artifacts/restricted/catalog/v2/activation/.authority-ledger/authority-consumption-ledger.jsonl",
    "artifacts/restricted/catalog/v2/approval/catalog-approval-request.json",
    "artifacts/restricted/catalog/v2/approval/catalog-approval-state-attestation.json",
    "artifacts/restricted/catalog/v2/approval/catalog-approval.json",
    "artifacts/restricted/catalog/v2/revisions/catalog-revision.json",
    "artifacts/restricted/catalog/v2/sqlite/initialization-issuance-context.json",
    "artifacts/restricted/catalog/v2/sqlite/seal-issuance-context.json",
    "artifacts/restricted/catalog/v2/sqlite/initialization-receipt.json",
    "artifacts/restricted/catalog/v2/sqlite/initialization-state-attestation.json",
    "artifacts/restricted/catalog/v2/sqlite/seal-state-attestation.json",
    "artifacts/restricted/catalog/v2/sqlite/real-manifest-seal-receipt.json",
    "artifacts/public/catalog/v2/sqlite-initialization-request.json",
    "artifacts/public/catalog/v2/sqlite-real-manifest-seal-request.json",
    "backend/schema/evaluation_manifest_v1/schema.sql",
    "backend/schema/evaluation_manifest_v1/logical-schema-manifest.json",
    "backend/schema/evaluation_manifest_v1/empty.sqlite3",
    "backend/schema/evaluation_manifest_v1/empty-proof.json",
    "artifacts/restricted/catalog/v2/release/final-audit/canonical-36.csv",
    "artifacts/restricted/catalog/v2/release/final-audit/canonical-36.json",
    "artifacts/restricted/catalog/v2/release/final-audit/canonical-36.md",
    "artifacts/restricted/catalog/v2/release/final-audit/canonical-36.parquet",
    "artifacts/restricted/catalog/v2/release/final-audit/projection-manifest.json",
    "artifacts/restricted/catalog/v2/release/phase-02-evidence-index.json",
    "artifacts/restricted/catalog/v2/release/phase-02-source-audit.json",
    ".planning/REQUIREMENTS.md",
    "backend/migrations/env.py",
    "backend/migrations/versions/0001_app_profiles.py",
    "backend/migrations/versions/0002_split_boundaries.py",
    "backend/migrations/versions/0003_real_manifest.py",
    "backend/src/itda/db/models.py",
    "backend/src/itda/db/repositories.py",
    "backend/src/itda/db/session.py",
    "backend/pyproject.toml",
    "backend/uv.lock",
    "web/package.json",
    "web/pnpm-lock.yaml",
    ".planning/config.json",
)
ALLOWED_NO_FOLLOW_RESULTS = frozenset(
    {
        "DIRECTORY_LSTAT_OPEN_NOFOLLOW_FSTAT_MATCH",
        "REGULAR_FILE_LSTAT_OPEN_NOFOLLOW_FSTAT_MATCH",
    }
)
ROW_KEYS = (
    "relpath",
    "entry_type",
    "mode",
    "size_bytes",
    "sha256",
    "no_follow_result",
)


class FingerprintError(ValueError):
    """Raised when a filesystem, manifest, or Git ancestry check fails closed."""


def _required_flag(name: str) -> int:
    value = getattr(os, name, None)
    if not isinstance(value, int) or value == 0:
        raise FingerprintError(f"{name} is required for no-follow verification")
    return value


O_NOFOLLOW = _required_flag("O_NOFOLLOW")
O_DIRECTORY = _required_flag("O_DIRECTORY")


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _mode(value: int) -> str:
    return f"0o{value:06o}"


def _checked_name(name: str) -> bytes:
    if name in {"", ".", ".."} or "/" in name or "\x00" in name:
        raise FingerprintError("invalid raw path component")
    try:
        encoded = name.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise FingerprintError("non-UTF-8 path component") from exc
    if encoded.decode("utf-8", errors="strict") != name:
        raise FingerprintError("path component does not round-trip as UTF-8")
    return encoded


def _checked_relpath(relpath: str) -> str:
    path = PurePosixPath(relpath)
    if (
        path.is_absolute()
        or str(path) != relpath
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise FingerprintError(f"non-canonical repository path: {relpath!r}")
    for part in path.parts:
        _checked_name(part)
    return relpath


def _same_object(before: os.stat_result, after: os.stat_result) -> None:
    if before.st_dev != after.st_dev or before.st_ino != after.st_ino:
        raise FingerprintError("scan/open replacement race detected")
    if stat.S_IFMT(before.st_mode) != stat.S_IFMT(after.st_mode):
        raise FingerprintError("entry type changed between lstat and fstat")


def _same_state(before: os.stat_result, after: os.stat_result) -> None:
    _same_object(before, after)
    if before.st_mode != after.st_mode or before.st_size != after.st_size:
        raise FingerprintError("entry changed while it was being fingerprinted")
    if abs(before.st_mtime_ns - after.st_mtime_ns) > 1_000:
        raise FingerprintError("entry mtime changed while it was being fingerprinted")


def _read_descriptor(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _row(
    *,
    relpath: str,
    entry_type: str,
    metadata: os.stat_result,
    sha256: str,
    no_follow_result: str,
) -> dict[str, object]:
    if no_follow_result not in ALLOWED_NO_FOLLOW_RESULTS:
        raise FingerprintError("unknown no_follow_result")
    return {
        "relpath": _checked_relpath(relpath),
        "entry_type": entry_type,
        "mode": _mode(metadata.st_mode),
        "size_bytes": metadata.st_size,
        "sha256": sha256,
        "no_follow_result": no_follow_result,
    }


def _fingerprint_regular_child(
    parent_descriptor: int,
    *,
    name: str,
    relpath: str,
    before: os.stat_result,
) -> dict[str, object]:
    try:
        child_descriptor = os.open(
            name,
            os.O_RDONLY | O_NOFOLLOW,
            dir_fd=parent_descriptor,
        )
        try:
            after = os.fstat(child_descriptor)
            _same_object(before, after)
            payload = _read_descriptor(child_descriptor)
            final = os.fstat(child_descriptor)
            _same_state(after, final)
        finally:
            os.close(child_descriptor)
    finally:
        os.close(parent_descriptor)
    if len(payload) != final.st_size:
        raise FingerprintError("regular-file size changed while hashing")
    return _row(
        relpath=relpath,
        entry_type="regular_file",
        metadata=final,
        sha256=_sha256_bytes(payload),
        no_follow_result="REGULAR_FILE_LSTAT_OPEN_NOFOLLOW_FSTAT_MATCH",
    )


def _scan_directory(
    descriptor: int,
    *,
    relpath: str,
    metadata: os.stat_result,
    executor: ThreadPoolExecutor,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    names = os.listdir(descriptor)
    encoded_names = [(_checked_name(name), name) for name in names]
    if len({encoded for encoded, _ in encoded_names}) != len(encoded_names):
        raise FingerprintError("duplicate raw-path alias")
    child_rows: list[dict[str, object]] = []
    pending_files: list[Future[dict[str, object]]] = []
    descendant_rows: list[dict[str, object]] = []
    for _, name in sorted(encoded_names):
        child_relpath = f"{relpath}/{name}"
        before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        entry_kind = stat.S_IFMT(before.st_mode)
        if entry_kind == stat.S_IFDIR:
            flags = os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW
            child_descriptor = os.open(name, flags, dir_fd=descriptor)
            try:
                after = os.fstat(child_descriptor)
                _same_object(before, after)
                child_row, nested = _scan_directory(
                    child_descriptor,
                    relpath=child_relpath,
                    metadata=after,
                    executor=executor,
                )
                _same_state(after, os.fstat(child_descriptor))
            finally:
                os.close(child_descriptor)
            child_rows.append(child_row)
            descendant_rows.extend(nested)
        elif entry_kind == stat.S_IFREG:
            pending_files.append(
                executor.submit(
                    _fingerprint_regular_child,
                    os.dup(descriptor),
                    name=name,
                    relpath=child_relpath,
                    before=before,
                )
            )
        else:
            raise FingerprintError("exceptional filesystem entries are not allowed")
    child_rows.extend(future.result() for future in pending_files)
    ordered_children = sorted(child_rows, key=lambda item: str(item["relpath"]).encode("utf-8"))
    directory_row = _row(
        relpath=relpath,
        entry_type="directory",
        metadata=metadata,
        sha256=canonical_sha256(ordered_children),
        no_follow_result="DIRECTORY_LSTAT_OPEN_NOFOLLOW_FSTAT_MATCH",
    )
    return directory_row, ordered_children + descendant_rows


def scan_catalog_tree(repo_root: Path, catalog_relpath: str = CATALOG_ROOT) -> dict[str, object]:
    """Return the complete descriptor-verified v1 tree without following links."""

    _checked_relpath(catalog_relpath)
    path = repo_root / catalog_relpath
    before = os.lstat(path)
    if not stat.S_ISDIR(before.st_mode):
        raise FingerprintError("catalog root is not a directory")
    descriptor = os.open(path, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    try:
        after = os.fstat(descriptor)
        _same_object(before, after)
        with ThreadPoolExecutor(max_workers=16, thread_name_prefix="catalog-v1-hash") as executor:
            root_row, descendants = _scan_directory(
                descriptor,
                relpath=catalog_relpath,
                metadata=after,
                executor=executor,
            )
        _same_state(after, os.fstat(descriptor))
    finally:
        os.close(descriptor)
    entries = sorted(
        [root_row, *descendants],
        key=lambda item: str(item["relpath"]).encode("utf-8"),
    )
    if len({str(item["relpath"]) for item in entries}) != len(entries):
        raise FingerprintError("duplicate catalog inventory path")
    return {
        "root_relpath": catalog_relpath,
        "exceptional_entry_allowlist": [],
        "entry_count": len(entries),
        "entries": entries,
        "tree_sha256": str(root_row["sha256"]),
    }


def _open_regular_repo_path(repo_descriptor: int, relpath: str) -> tuple[int, os.stat_result]:
    parts = PurePosixPath(_checked_relpath(relpath)).parts
    current = os.dup(repo_descriptor)
    try:
        for part in parts[:-1]:
            next_descriptor = os.open(
                part,
                os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW,
                dir_fd=current,
            )
            os.close(current)
            current = next_descriptor
        before = os.stat(parts[-1], dir_fd=current, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode):
            raise FingerprintError(f"required regular file has wrong type: {relpath}")
        result = os.open(parts[-1], os.O_RDONLY | O_NOFOLLOW, dir_fd=current)
        after = os.fstat(result)
        _same_object(before, after)
        return result, after
    finally:
        os.close(current)


def _regular_file_record(
    repo_root: Path,
    repo_descriptor: int,
    relpath: str,
) -> tuple[dict[str, object], bytes]:
    descriptor, metadata = _open_regular_repo_path(repo_descriptor, relpath)
    try:
        payload = _read_descriptor(descriptor)
        final = os.fstat(descriptor)
        _same_state(metadata, final)
    finally:
        os.close(descriptor)
    if len(payload) != final.st_size:
        raise FingerprintError(f"file size changed while hashing: {relpath}")
    return (
        _row(
            relpath=relpath,
            entry_type="regular_file",
            metadata=final,
            sha256=_sha256_bytes(payload),
            no_follow_result="REGULAR_FILE_LSTAT_OPEN_NOFOLLOW_FSTAT_MATCH",
        ),
        payload,
    )


def _regular_file_row(repo_root: Path, repo_descriptor: int, relpath: str) -> dict[str, object]:
    return _regular_file_record(repo_root, repo_descriptor, relpath)[0]


def _regular_file_record_owned(
    repo_root: Path,
    repo_descriptor: int,
    relpath: str,
) -> tuple[dict[str, object], bytes]:
    try:
        return _regular_file_record(repo_root, repo_descriptor, relpath)
    finally:
        os.close(repo_descriptor)


def planning_history(repo_root: Path) -> dict[str, object]:
    """Fingerprint exactly the completed 02-01..08 PLAN/SUMMARY files."""

    expected = tuple(
        f"{PHASE_ROOT}/{plan_id}-{kind}.md"
        for plan_id in COMPLETED_PLAN_IDS
        for kind in ("PLAN", "SUMMARY")
    )
    repo_descriptor = os.open(
        repo_root,
        os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW,
    )
    try:
        with ThreadPoolExecutor(max_workers=16, thread_name_prefix="planning-history") as executor:
            futures = [
                executor.submit(
                    _regular_file_record_owned,
                    repo_root,
                    os.dup(repo_descriptor),
                    path,
                )
                for path in expected
            ]
            entries = [future.result()[0] for future in futures]
    finally:
        os.close(repo_descriptor)
    entries.sort(key=lambda item: str(item["relpath"]).encode("utf-8"))
    return {
        "required_file_count": 16,
        "entries": entries,
        "tree_sha256": canonical_sha256(entries),
    }


def _run_git(repo_root: Path, *arguments: str, text: bool = False) -> bytes | str:
    completed = subprocess.run(
        ["rtk", "git", *arguments],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=text,
    )
    return completed.stdout


def _declared_parent_paths(repo_root: Path) -> tuple[str, ...]:
    declared: set[str] = set()
    for plan_id in COMPLETED_PLAN_IDS:
        plan_path = repo_root / PHASE_ROOT / f"{plan_id}-PLAN.md"
        text = plan_path.read_text(encoding="utf-8")
        match = __import__("re").search(
            r"(?m)^files_modified:\n(?P<body>(?:  - [^\n]+\n)+)",
            text,
        )
        if match is None:
            raise FingerprintError(f"missing files_modified inventory in {plan_id}")
        for raw in match.group("body").splitlines():
            path = raw.removeprefix("  - ").strip().strip("\"'")
            if path.startswith(".planning/") or path.startswith("artifacts/restricted/"):
                continue
            _checked_relpath(path)
            declared.add(path)
    return tuple(sorted(declared, key=lambda item: item.encode("utf-8")))


def _index_entries(repo_root: Path, declared_paths: Iterable[str]) -> dict[str, tuple[str, str]]:
    indexed: dict[str, tuple[str, str]] = {}
    declared_tuple = tuple(declared_paths)
    raw = _run_git(repo_root, "ls-files", "--stage", "-z", "--", *declared_tuple)
    assert isinstance(raw, bytes)
    for record in raw.split(b"\0"):
        if not record:
            continue
        prefix, raw_path = record.split(b"\t", 1)
        mode, oid, stage = prefix.decode("ascii").split(" ")
        if stage != "0":
            raise FingerprintError("Git conflict stage found in protected ancestry")
        try:
            path = raw_path.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise FingerprintError("non-UTF-8 Git index path") from exc
        _checked_relpath(path)
        if path in indexed:
            raise FingerprintError("duplicate Git index path")
        indexed[path] = (mode, oid)
    for declared in declared_tuple:
        if declared in indexed or any(path.startswith(f"{declared}/") for path in indexed):
            continue
        raise FingerprintError(f"declared prior-plan parent is not tracked: {declared}")
    if not indexed:
        raise FingerprintError("no tracked source/config parents were derived")
    return indexed


def tracked_source_config(repo_root: Path) -> dict[str, object]:
    """Bind worktree bytes to the stage-0 Git index for prior-plan parents."""

    indexed = _index_entries(repo_root, _declared_parent_paths(repo_root))
    repo_descriptor = os.open(
        repo_root,
        os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW,
    )
    rows: list[dict[str, object]] = []
    object_format = _run_git(
        repo_root,
        "rev-parse",
        "--show-object-format",
        text=True,
    )
    assert isinstance(object_format, str)
    algorithm = object_format.strip()
    try:
        ordered_paths = sorted(indexed, key=lambda item: item.encode("utf-8"))
        with ThreadPoolExecutor(max_workers=16, thread_name_prefix="source-config") as executor:
            futures = {
                relpath: executor.submit(
                    _regular_file_record_owned,
                    repo_root,
                    os.dup(repo_descriptor),
                    relpath,
                )
                for relpath in ordered_paths
            }
            records = {relpath: future.result() for relpath, future in futures.items()}
        for relpath in ordered_paths:
            worktree, payload = records[relpath]
            index_mode, blob_oid = indexed[relpath]
            object_hash = hashlib.new(algorithm)
            object_hash.update(f"blob {len(payload)}\0".encode("ascii"))
            object_hash.update(payload)
            if object_hash.hexdigest() != blob_oid:
                raise FingerprintError(f"worktree/index substitution detected: {relpath}")
            expected_permissions = "755" if index_mode == "100755" else "644"
            if index_mode not in {"100644", "100755"}:
                raise FingerprintError(f"unsupported stage-0 index mode: {index_mode}")
            if str(worktree["mode"])[-3:] != expected_permissions:
                raise FingerprintError(f"worktree/index mode mismatch: {relpath}")
            rows.append(
                {
                    "worktree": worktree,
                    "index_mode": index_mode,
                    "index_blob_oid": blob_oid,
                }
            )
    finally:
        os.close(repo_descriptor)
    return {
        "entry_count": len(rows),
        "entries": rows,
        "inventory_sha256": canonical_sha256(rows),
    }


def build_manifest(repo_root: Path) -> dict[str, object]:
    fields: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "catalog_v1": scan_catalog_tree(repo_root),
        "planning_history": planning_history(repo_root),
        "tracked_source_config": tracked_source_config(repo_root),
    }
    return {**fields, "manifest_sha256": canonical_sha256(fields)}


def _load_manifest(path: Path) -> dict[str, object]:
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise FingerprintError("manifest path is not a regular file")
    descriptor = os.open(path, os.O_RDONLY | O_NOFOLLOW)
    try:
        after = os.fstat(descriptor)
        _same_object(before, after)
        raw = _read_descriptor(descriptor)
        _same_state(after, os.fstat(descriptor))
    finally:
        os.close(descriptor)
    parsed = json.loads(raw)
    if not isinstance(parsed, dict) or raw != canonical_json_bytes(parsed):
        raise FingerprintError("manifest is not canonical JSON")
    return parsed


def verify_manifest(repo_root: Path, manifest_path: Path) -> dict[str, object]:
    recorded = _load_manifest(manifest_path)
    expected = build_manifest(repo_root)
    if recorded != expected:
        raise FingerprintError("immutability manifest does not match live recomputation")
    return expected


def _manifest_self_hash(manifest: dict[str, object], field: str) -> str:
    recorded = manifest.get(field)
    if not isinstance(recorded, str) or len(recorded) != 64:
        raise FingerprintError(f"invalid {field}")
    fields = {key: value for key, value in manifest.items() if key != field}
    if canonical_sha256(fields) != recorded:
        raise FingerprintError(f"{field} self hash mismatch")
    return recorded


def _worktree_status_rows(
    repo_root: Path,
    paths: Iterable[str],
) -> tuple[tuple[str, str], ...]:
    completed = subprocess.run(
        [
            "rtk",
            "proxy",
            "git",
            "status",
            "--porcelain=v2",
            "-z",
            "--untracked-files=no",
            "--",
            *tuple(paths),
        ],
        cwd=repo_root,
        check=True,
        capture_output=True,
    )
    rows: list[tuple[str, str]] = []
    for record in completed.stdout.split(b"\0"):
        if not record:
            continue
        text = record.decode("utf-8", errors="strict")
        status = text.split(" ", 2)[:2]
        rows.append((status[-1], "tracked-change"))
    return tuple(rows)


def _owner_commit_identity(
    repo_root: Path,
    *,
    relpath: str,
    plan_id: str,
    commit: str,
) -> dict[str, str]:
    try:
        full = _run_git(
            repo_root,
            "rev-parse",
            "--verify",
            f"{commit}^{{commit}}",
            text=True,
        )
        assert isinstance(full, str)
        full = full.strip()
        ancestry = subprocess.run(
            ["rtk", "git", "merge-base", "--is-ancestor", full, "HEAD"],
            cwd=repo_root,
            check=False,
            capture_output=True,
        )
        if ancestry.returncode != 0:
            raise FingerprintError("owner commit is not in HEAD ancestry")
        subject = _run_git(repo_root, "show", "-s", "--format=%s", full, text=True)
        assert isinstance(subject, str)
        if f"({plan_id})" not in subject:
            raise FingerprintError("owner commit plan identity mismatch")
        raw = _run_git(repo_root, "ls-tree", "-z", full, "--", relpath)
        assert isinstance(raw, bytes)
        records = [item for item in raw.split(b"\0") if item]
        if len(records) != 1:
            raise FingerprintError("owner commit path identity is missing or ambiguous")
        header, raw_path = records[0].split(b"\t", 1)
        mode, kind, oid = header.decode("ascii").split(" ")
        if kind != "blob" or raw_path.decode("utf-8") != relpath:
            raise FingerprintError("owner commit path is not the expected regular blob")
    except (subprocess.CalledProcessError, UnicodeError, ValueError) as exc:
        if isinstance(exc, FingerprintError):
            raise
        raise FingerprintError("owner commit verification failed") from exc
    return {
        "owner_plan_id": plan_id,
        "owner_commit": full,
        "owner_commit_mode": mode,
        "owner_commit_blob_oid": oid,
    }


def classify_successor_delta(
    repo_root: Path,
    recorded: dict[str, object],
    current: dict[str, object],
) -> dict[str, object]:
    """Classify only the exact completed Plan 21/25 tracked-source evolution."""

    _manifest_self_hash(recorded, "manifest_sha256")
    _manifest_self_hash(current, "manifest_sha256")
    for section in ("catalog_v1", "planning_history"):
        if recorded.get(section) != current.get(section):
            raise FingerprintError(f"protected {section} section drifted")

    old_source = recorded.get("tracked_source_config")
    new_source = current.get("tracked_source_config")
    if not isinstance(old_source, dict) or not isinstance(new_source, dict):
        raise FingerprintError("tracked_source_config section is missing")
    if old_source.get("inventory_sha256") != EXPECTED_RECORDED_INVENTORY_SHA256:
        raise FingerprintError("wrong predecessor tracked-source root")
    if new_source.get("inventory_sha256") != EXPECTED_CURRENT_INVENTORY_SHA256:
        raise FingerprintError("wrong current tracked-source root; not exact four-path delta")
    old_entries = old_source.get("entries")
    new_entries = new_source.get("entries")
    if not isinstance(old_entries, list) or not isinstance(new_entries, list):
        raise FingerprintError("tracked-source entries are missing")

    def by_path(entries: list[object]) -> dict[str, dict[str, object]]:
        result: dict[str, dict[str, object]] = {}
        for value in entries:
            if not isinstance(value, dict) or not isinstance(value.get("worktree"), dict):
                raise FingerprintError("malformed tracked-source row")
            relpath = value["worktree"].get("relpath")
            if not isinstance(relpath, str) or relpath in result:
                raise FingerprintError("duplicate or malformed tracked-source path")
            result[relpath] = value
        return result

    old_by_path = by_path(old_entries)
    new_by_path = by_path(new_entries)
    if set(old_by_path) != set(new_by_path):
        raise FingerprintError("tracked-source inventory path set drifted")
    changed = tuple(
        sorted(
            (path for path in old_by_path if old_by_path[path] != new_by_path[path]),
            key=str.encode,
        )
    )
    if changed != EXPECTED_DELTA_PATHS:
        raise FingerprintError("tracked-source delta is not the exact four-path set")
    if _worktree_status_rows(repo_root, EXPECTED_DELTA_PATHS):
        raise FingerprintError("tracked-source delta paths are not clean against stage 0")

    rows: list[dict[str, object]] = []
    for relpath in changed:
        plan_id, commit = DELTA_OWNER_COMMITS[relpath]
        owner = _owner_commit_identity(
            repo_root,
            relpath=relpath,
            plan_id=plan_id,
            commit=commit,
        )
        current_row = new_by_path[relpath]
        if (
            current_row.get("index_mode") != owner["owner_commit_mode"]
            or current_row.get("index_blob_oid") != owner["owner_commit_blob_oid"]
        ):
            raise FingerprintError("current blob is not attributable to owner commit")
        rows.append(
            {
                "relpath": relpath,
                "recorded": copy.deepcopy(old_by_path[relpath]),
                "current": copy.deepcopy(current_row),
                **owner,
            }
        )

    catalog = recorded["catalog_v1"]
    planning = recorded["planning_history"]
    assert isinstance(catalog, dict) and isinstance(planning, dict)
    result = {
        "recorded_inventory_sha256": old_source["inventory_sha256"],
        "current_inventory_sha256": new_source["inventory_sha256"],
        "catalog_v1_tree_sha256": catalog["tree_sha256"],
        "planning_history_tree_sha256": planning["tree_sha256"],
        "delta_rows": rows,
        "exceptional_delta_allowlist": [],
        "classification": "EXACT_LATER_COMPLETED_SOURCE_EVOLUTION",
    }
    _assert_membership_free_payload(result)
    return result


def diagnose_successor(repo_root: Path, predecessor_path: Path) -> dict[str, object]:
    predecessor = _load_manifest(predecessor_path)
    current = build_manifest(repo_root)
    return classify_successor_delta(repo_root, predecessor, current)


def build_successor_manifest(
    repo_root: Path,
    predecessor_path: Path,
) -> dict[str, object]:
    first = diagnose_successor(repo_root, predecessor_path)
    second = diagnose_successor(repo_root, predecessor_path)
    if canonical_json_bytes(first) != canonical_json_bytes(second):
        raise FingerprintError("successor diagnostic changed between derivations")
    predecessor = _load_manifest(predecessor_path)
    raw_predecessor, _ = _stable_regular_payload(predecessor_path)
    fields: dict[str, object] = {
        "schema_version": SUCCESSOR_SCHEMA_VERSION,
        "predecessor": {
            "relpath": PREDECESSOR_TARGET,
            "file_sha256": _sha256_bytes(raw_predecessor),
            "manifest_sha256": predecessor["manifest_sha256"],
        },
        "catalog_v1_tree_sha256": first["catalog_v1_tree_sha256"],
        "planning_history_tree_sha256": first["planning_history_tree_sha256"],
        "recorded_inventory_sha256": first["recorded_inventory_sha256"],
        "current_inventory_sha256": first["current_inventory_sha256"],
        "tracked_source_delta": first["delta_rows"],
        "exceptional_delta_allowlist": [],
        "migration_reason": "LATER_COMPLETED_SOURCE_EVOLUTION",
    }
    unordered = {**fields, "successor_sha256": canonical_sha256(fields)}
    successor = {key: unordered[key] for key in SUCCESSOR_KEYS}
    if tuple(successor) != SUCCESSOR_KEYS:
        raise FingerprintError("successor schema key order is not closed")
    _assert_membership_free_payload(successor)
    return successor


def verify_successor_manifest(
    repo_root: Path,
    predecessor_path: Path,
    recorded: dict[str, object],
) -> dict[str, object]:
    if tuple(recorded) != SUCCESSOR_KEYS:
        raise FingerprintError("successor schema is not closed or canonically ordered")
    if recorded.get("schema_version") != SUCCESSOR_SCHEMA_VERSION:
        raise FingerprintError("wrong successor schema version")
    _manifest_self_hash(recorded, "successor_sha256")
    delta = recorded.get("tracked_source_delta")
    if (
        not isinstance(delta, list)
        or tuple(row.get("relpath") if isinstance(row, dict) else None for row in delta)
        != EXPECTED_DELTA_PATHS
    ):
        raise FingerprintError("successor delta rows are not canonically ordered")
    expected = build_successor_manifest(repo_root, predecessor_path)
    if recorded != expected:
        raise FingerprintError("successor does not match current verified lineage")
    return expected


def _write_no_replace(path: Path, payload: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = os.lstat(path.parent)
    if not stat.S_ISDIR(parent.st_mode):
        raise FingerprintError("manifest parent is not a directory")
    parent_descriptor = os.open(path.parent, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    temporary_name = f".{path.name}.{secrets.token_hex(16)}.tmp"
    descriptor = os.open(
        temporary_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW,
        0o600,
        dir_fd=parent_descriptor,
    )
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise FingerprintError("short write while publishing manifest")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.link(
            temporary_name,
            path.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        os.fsync(parent_descriptor)
    finally:
        try:
            os.unlink(temporary_name, dir_fd=parent_descriptor)
        finally:
            os.close(parent_descriptor)


def _stable_regular_payload(path: Path) -> tuple[bytes, os.stat_result]:
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise FingerprintError("protected path is not a regular file")
    descriptor = os.open(path, os.O_RDONLY | O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        _same_object(before, opened)
        payload = _read_descriptor(descriptor)
        final = os.fstat(descriptor)
        _same_state(opened, final)
    finally:
        os.close(descriptor)
    if len(payload) != final.st_size:
        raise FingerprintError("protected file size changed during read")
    return payload, final


def _publish_exact_existing(path: Path, payload: bytes) -> str:
    """Publish one private file or recover only an exact stable existing file."""

    if path.exists() or path.is_symlink():
        existing, metadata = _stable_regular_payload(path)
        if existing != payload or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1:
            raise FingerprintError("existing protected publication collision")
        return "ALREADY_PRESENT_VERIFIED"
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_before = os.lstat(path.parent)
    if not stat.S_ISDIR(parent_before.st_mode):
        raise FingerprintError("protected publication parent is not a directory")
    parent_descriptor = os.open(path.parent, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    temporary_name = f".{path.name}.{secrets.token_hex(16)}.tmp"
    descriptor = os.open(
        temporary_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW,
        0o600,
        dir_fd=parent_descriptor,
    )
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise FingerprintError("short protected publication write")
            offset += written
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        try:
            os.link(
                temporary_name,
                path.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileExistsError:
            existing, metadata = _stable_regular_payload(path)
            if (
                existing != payload
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1
            ):
                raise FingerprintError("existing protected publication collision") from None
            return "ALREADY_PRESENT_VERIFIED"
        os.fsync(parent_descriptor)
    finally:
        try:
            os.unlink(temporary_name, dir_fd=parent_descriptor)
        finally:
            os.close(parent_descriptor)
    published, metadata = _stable_regular_payload(path)
    if published != payload or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1:
        raise FingerprintError("published protected bytes failed verification")
    return "PUBLISHED"


def _assert_membership_free_payload(value: object) -> None:
    forbidden_keys = {
        "members",
        "catalog_members",
        "dev_members",
        "blind_members",
        "ordered_catalog_ids",
        "member_rows",
        "member_ids",
        "member_order",
        "complement",
        "per_member_digests",
        "database_path",
        "database_uri",
        "populated_database_path",
        "raw_authority",
        "raw_token",
        "raw_nonce",
        "credential",
        "credentials",
        "sidecar_bytes",
    }

    def walk(item: object) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                if key.casefold() in forbidden_keys:
                    raise FingerprintError(f"forbidden protected field: {key}")
                walk(child)
        elif isinstance(item, list | tuple):
            for child in item:
                walk(child)
        elif isinstance(item, str):
            lowered = item.casefold()
            if (
                "sqlite:///" in lowered
                or "synthetic:blind:" in lowered
                or lowered.startswith("place:")
            ):
                raise FingerprintError("forbidden protected value")

    walk(value)


def _git_stage_identity(repo_root: Path, relpath: str) -> dict[str, str] | None:
    completed = subprocess.run(
        ["rtk", "proxy", "git", "ls-files", "--stage", "-z", "--", relpath],
        cwd=repo_root,
        check=True,
        capture_output=True,
    )
    records = [item for item in completed.stdout.split(b"\0") if item]
    if not records:
        return None
    if len(records) != 1:
        raise FingerprintError("protected path has ambiguous Git index identity")
    header, raw_path = records[0].split(b"\t", 1)
    mode, oid, stage = header.decode("ascii").split(" ")
    if stage != "0" or raw_path.decode("utf-8") != relpath:
        raise FingerprintError("protected path is not a clean stage-0 identity")
    return {"index_mode": mode, "index_blob_oid": oid}


def _protected_file_owner(repo_root: Path, relpath: str) -> dict[str, object]:
    _checked_relpath(relpath)
    payload, metadata = _stable_regular_payload(repo_root / relpath)
    return {
        "owner": f"file:{relpath}",
        "kind": "regular_file",
        "relpath": relpath,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": _mode(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "link_count": metadata.st_nlink,
        "size_bytes": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
        "sha256": _sha256_bytes(payload),
        "git_stage0": _git_stage_identity(repo_root, relpath),
        "no_follow_result": "REGULAR_FILE_LSTAT_OPEN_NOFOLLOW_FSTAT_MATCH",
    }


def _catalog_tree_owner(repo_root: Path) -> dict[str, object]:
    path = repo_root / CATALOG_ROOT
    before = os.lstat(path)
    if not stat.S_ISDIR(before.st_mode):
        raise FingerprintError("protected catalog tree root is not a directory")
    descriptor = os.open(path, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        _same_object(before, opened)
        tree = scan_catalog_tree(repo_root)
        _same_state(opened, os.fstat(descriptor))
    finally:
        os.close(descriptor)
    return {
        "owner": "tree:catalog_v1",
        "kind": "directory_tree",
        "relpath": CATALOG_ROOT,
        "device": opened.st_dev,
        "inode": opened.st_ino,
        "mode": _mode(opened.st_mode),
        "uid": opened.st_uid,
        "gid": opened.st_gid,
        "link_count": opened.st_nlink,
        "size_bytes": opened.st_size,
        "mtime_ns": opened.st_mtime_ns,
        "entry_count": tree["entry_count"],
        "tree_sha256": tree["tree_sha256"],
        "git_stage0": None,
        "no_follow_result": "DIRECTORY_LSTAT_OPEN_NOFOLLOW_FSTAT_MATCH",
    }


def _opaque_sqlite_owner(repo_root: Path) -> dict[str, object]:
    sqlite_root = repo_root / "artifacts/restricted/catalog/v2/sqlite"
    before = os.lstat(sqlite_root)
    if not stat.S_ISDIR(before.st_mode):
        raise FingerprintError("restricted SQLite owner root is not a directory")
    receipt_payload, _ = _stable_regular_payload(sqlite_root / "real-manifest-seal-receipt.json")
    receipt = json.loads(receipt_payload)
    if not isinstance(receipt, dict) or receipt_payload != canonical_json_bytes(receipt):
        raise FingerprintError("SQLite seal receipt is not canonical")
    expected_database_sha256 = receipt.get("database_sha256")
    if not isinstance(expected_database_sha256, str):
        raise FingerprintError("SQLite seal receipt lacks the file digest")
    candidates: list[tuple[Path, bytes, os.stat_result]] = []

    def visit(directory: Path) -> None:
        for entry in os.scandir(directory):
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise FingerprintError("restricted SQLite tree contains a symlink")
            if stat.S_ISDIR(metadata.st_mode):
                visit(Path(entry.path))
            elif stat.S_ISREG(metadata.st_mode):
                path = Path(entry.path)
                if path.suffix == ".json":
                    continue
                payload, final = _stable_regular_payload(path)
                if _sha256_bytes(payload) == expected_database_sha256:
                    candidates.append((path, payload, final))
            else:
                raise FingerprintError("restricted SQLite tree has an exceptional entry")

    visit(sqlite_root)
    if len(candidates) != 1:
        raise FingerprintError("opaque SQLite owner cardinality is not exactly one")
    database_path, payload, metadata = candidates[0]
    sibling_names = {entry.name for entry in os.scandir(database_path.parent)}
    sidecar_names = {
        f"{database_path.name}-journal",
        f"{database_path.name}-wal",
        f"{database_path.name}-shm",
    }
    if sibling_names & sidecar_names:
        raise FingerprintError("opaque SQLite owner has a live sidecar")
    tracked = subprocess.run(
        [
            "rtk",
            "proxy",
            "git",
            "ls-files",
            "--error-unmatch",
            str(database_path),
        ],
        cwd=repo_root,
        check=False,
        capture_output=True,
    )
    if tracked.returncode == 0:
        raise FingerprintError("opaque SQLite owner must remain untracked")
    selected = {
        "counts": receipt.get("counts"),
        "database_sha256": receipt.get("database_sha256"),
        "logical_schema_sha256": receipt.get("logical_schema_sha256"),
        "logical_seal_sha256": receipt.get("logical_seal_sha256"),
        "membership_sha256": receipt.get("membership_sha256"),
        "integrity_check": receipt.get("integrity_check"),
        "foreign_key_check_count": receipt.get("foreign_key_check_count"),
        "sidecars_absent": not receipt.get("sidecars"),
    }
    if selected["database_sha256"] != _sha256_bytes(payload):
        raise FingerprintError("opaque SQLite file identity differs from sealed receipt")
    _assert_membership_free_payload(selected)
    return {
        "owner": "opaque:phase2_sqlite_manifest",
        "kind": "opaque_sqlite_identity",
        "logical_alias": "phase2_sqlite_manifest",
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": _mode(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "link_count": metadata.st_nlink,
        "size_bytes": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
        "file_sha256": _sha256_bytes(payload),
        **selected,
        "git_stage0": None,
        "no_follow_result": "REGULAR_FILE_LSTAT_OPEN_NOFOLLOW_FSTAT_MATCH",
    }


def _protected_owner_paths() -> tuple[str, ...]:
    completed = tuple(
        f"{PHASE_ROOT}/{plan_id}-{kind}.md"
        for plan_id in PROTECTED_COMPLETED_PLAN_IDS
        for kind in ("PLAN", "SUMMARY")
    )
    history = tuple(f"{PHASE_ROOT}/{name}" for name in PROTECTED_HISTORY_FILES)
    paths = (*PROTECTED_FIXED_FILES, *completed, *history)
    if len(paths) != len(set(paths)):
        raise FingerprintError("protected owner registry contains duplicates")
    return tuple(sorted(paths, key=str.encode))


def build_protected_manifest(
    repo_root: Path,
    *,
    plan_id: str,
    stage: str,
) -> dict[str, object]:
    if plan_id not in {"02-60", "02-61", "02-62"}:
        raise FingerprintError("protected manifest plan ID is not allowlisted")
    if stage not in {"before", "after"}:
        raise FingerprintError("protected manifest stage is not closed")
    owners = [_catalog_tree_owner(repo_root)]
    owners.extend(_protected_file_owner(repo_root, path) for path in _protected_owner_paths())
    owners.append(_opaque_sqlite_owner(repo_root))
    owners.sort(key=lambda row: str(row["owner"]).encode("utf-8"))
    if len({str(row["owner"]) for row in owners}) != len(owners):
        raise FingerprintError("protected logical owner is duplicated")
    absences = []
    for relpath in PROTECTED_REQUIRED_ABSENCES:
        path = repo_root / relpath
        if path.exists() or path.is_symlink():
            raise FingerprintError("required absent protected owner is present")
        absences.append({"relpath": relpath, "required_state": "ABSENT"})
    identity_rows_sha256 = canonical_sha256(owners)
    protected_set_sha256 = canonical_sha256({"owners": owners, "required_absences": absences})
    fields: dict[str, object] = {
        "schema_version": PROTECTED_MANIFEST_SCHEMA_VERSION,
        "plan_id": plan_id,
        "stage": stage,
        "owner_count": len(owners),
        "owners": owners,
        "required_absences": absences,
        "identity_rows_sha256": identity_rows_sha256,
        "protected_set_sha256": protected_set_sha256,
    }
    unordered = {
        **fields,
        "protected_manifest_sha256": canonical_sha256(fields),
    }
    result = {key: unordered[key] for key in PROTECTED_MANIFEST_KEYS}
    if tuple(result) != PROTECTED_MANIFEST_KEYS:
        raise FingerprintError("protected manifest key order is not closed")
    _assert_membership_free_payload(result)
    return result


def validate_protected_manifest(
    repo_root: Path,
    recorded: dict[str, object],
    *,
    plan_id: str,
    stage: str,
) -> dict[str, object]:
    if tuple(recorded) != PROTECTED_MANIFEST_KEYS:
        raise FingerprintError("protected manifest schema is not closed")
    if (
        recorded.get("schema_version") != PROTECTED_MANIFEST_SCHEMA_VERSION
        or recorded.get("plan_id") != plan_id
        or recorded.get("stage") != stage
    ):
        raise FingerprintError("protected manifest coordinates are stale")
    _manifest_self_hash(recorded, "protected_manifest_sha256")
    _assert_membership_free_payload(recorded)
    expected = build_protected_manifest(repo_root, plan_id=plan_id, stage=stage)
    if recorded != expected:
        raise FingerprintError("protected manifest does not match live owner identities")
    return expected


def compare_protected_manifests(
    before: dict[str, object],
    after: dict[str, object],
) -> str:
    for value in (before, after):
        if tuple(value) != PROTECTED_MANIFEST_KEYS:
            raise FingerprintError("protected manifest comparison schema is not closed")
        _manifest_self_hash(value, "protected_manifest_sha256")
        _assert_membership_free_payload(value)
    if before.get("plan_id") != after.get("plan_id"):
        raise FingerprintError("protected manifest plan owner differs")
    if before.get("stage") != "before" or after.get("stage") != "after":
        raise FingerprintError("protected manifest comparison stages are invalid")
    for key in (
        "schema_version",
        "owner_count",
        "owners",
        "required_absences",
        "identity_rows_sha256",
        "protected_set_sha256",
    ):
        if before.get(key) != after.get(key):
            raise FingerprintError("protected owner set is not exactly equal")
    return "EXACT_EQUAL"


def _repo_root() -> Path:
    output = _run_git(Path.cwd(), "rev-parse", "--show-toplevel", text=True)
    assert isinstance(output, str)
    return Path(output.strip())


def _cli_path(repo_root: Path, value: Path) -> Path:
    resolved = (value if value.is_absolute() else Path.cwd() / value).resolve()
    try:
        resolved.relative_to(repo_root.resolve())
    except ValueError as exc:
        raise FingerprintError("lineage artifact path escapes the repository") from exc
    return resolved


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--build", type=Path, metavar="MANIFEST")
    modes.add_argument("--verify", type=Path, metavar="MANIFEST")
    modes.add_argument("--recompute-v1-tree", action="store_true")
    modes.add_argument("--recompute-history-tree", action="store_true")
    modes.add_argument("--capture-protected-manifest", type=Path, metavar="MANIFEST")
    modes.add_argument("--verify-protected-manifest", type=Path, metavar="MANIFEST")
    modes.add_argument(
        "--compare-protected-manifests",
        nargs=2,
        type=Path,
        metavar=("BEFORE", "AFTER"),
    )
    modes.add_argument("--diagnose-successor", type=Path, metavar="PREDECESSOR")
    modes.add_argument("--build-successor", type=Path, metavar="SUCCESSOR")
    modes.add_argument("--verify-successor", type=Path, metavar="SUCCESSOR")
    parser.add_argument("--predecessor", type=Path)
    parser.add_argument("--plan-id")
    parser.add_argument("--stage", choices=("before", "after"))
    parser.add_argument("--require-exact", action="store_true")
    return parser


def _exact_repo_target(repo_root: Path, value: Path, expected: str) -> Path:
    path = _cli_path(repo_root, value)
    try:
        relpath = path.relative_to(repo_root).as_posix()
    except ValueError as exc:
        raise FingerprintError("protected target escapes repository") from exc
    if relpath != expected:
        raise FingerprintError(f"protected target must be {expected}")
    return path


def _guard_relpath(plan_id: str, stage: str) -> str:
    if plan_id not in {"02-60", "02-61", "02-62"} or stage not in {
        "before",
        "after",
    }:
        raise FingerprintError("guard coordinates are not allowlisted")
    return (
        "artifacts/restricted/catalog/v2/release/gap-closure-guards/"
        f"{plan_id}-protected-{stage}.json"
    )


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repo_root = _repo_root()
    if args.build is not None:
        manifest = build_manifest(repo_root)
        first_bytes = canonical_json_bytes(manifest)
        second_bytes = canonical_json_bytes(json.loads(first_bytes))
        if first_bytes != second_bytes:
            raise FingerprintError("two canonical builds were not byte-identical")
        output = _cli_path(repo_root, args.build)
        _write_no_replace(output, first_bytes)
        print(manifest["manifest_sha256"])
    elif args.verify is not None:
        target = _cli_path(repo_root, args.verify)
        print(verify_manifest(repo_root, target)["manifest_sha256"])
    elif args.recompute_v1_tree:
        print(scan_catalog_tree(repo_root)["tree_sha256"])
    elif args.recompute_history_tree:
        print(planning_history(repo_root)["tree_sha256"])
    elif args.capture_protected_manifest is not None:
        if args.plan_id is None or args.stage is None:
            raise FingerprintError("protected manifest requires --plan-id and --stage")
        target = _exact_repo_target(
            repo_root,
            args.capture_protected_manifest,
            _guard_relpath(args.plan_id, args.stage),
        )
        manifest = build_protected_manifest(
            repo_root,
            plan_id=args.plan_id,
            stage=args.stage,
        )
        _publish_exact_existing(target, canonical_json_bytes(manifest))
        print(manifest["protected_manifest_sha256"])
    elif args.verify_protected_manifest is not None:
        if args.plan_id is None or args.stage is None:
            raise FingerprintError("protected manifest requires --plan-id and --stage")
        target = _exact_repo_target(
            repo_root,
            args.verify_protected_manifest,
            _guard_relpath(args.plan_id, args.stage),
        )
        recorded = _load_manifest(target)
        verified = validate_protected_manifest(
            repo_root,
            recorded,
            plan_id=args.plan_id,
            stage=args.stage,
        )
        print(verified["protected_manifest_sha256"])
    elif args.compare_protected_manifests is not None:
        if not args.require_exact:
            raise FingerprintError("protected comparison requires --require-exact")
        before = _load_manifest(_cli_path(repo_root, args.compare_protected_manifests[0]))
        after = _load_manifest(_cli_path(repo_root, args.compare_protected_manifests[1]))
        print(compare_protected_manifests(before, after))
    elif args.diagnose_successor is not None:
        predecessor = _exact_repo_target(
            repo_root,
            args.diagnose_successor,
            PREDECESSOR_TARGET,
        )
        print(canonical_json_bytes(diagnose_successor(repo_root, predecessor)).decode())
    elif args.build_successor is not None:
        if args.predecessor is None:
            raise FingerprintError("successor build requires --predecessor")
        target = _exact_repo_target(repo_root, args.build_successor, SUCCESSOR_TARGET)
        predecessor = _exact_repo_target(
            repo_root,
            args.predecessor,
            PREDECESSOR_TARGET,
        )
        successor = build_successor_manifest(repo_root, predecessor)
        _publish_exact_existing(target, canonical_json_bytes(successor))
        print(successor["successor_sha256"])
    else:
        assert args.verify_successor is not None
        if args.predecessor is None:
            raise FingerprintError("successor verification requires --predecessor")
        target = _exact_repo_target(repo_root, args.verify_successor, SUCCESSOR_TARGET)
        predecessor = _exact_repo_target(
            repo_root,
            args.predecessor,
            PREDECESSOR_TARGET,
        )
        recorded = _load_manifest(target)
        print(verify_successor_manifest(repo_root, predecessor, recorded)["successor_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
