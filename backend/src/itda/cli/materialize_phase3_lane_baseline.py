"""Materialize an exact Phase 3 lane baseline without protected rescoring."""

from __future__ import annotations

import argparse
import json
import os
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from itda.contracts.phase3_lane_baseline import Phase3LaneAuthorityBundle
from itda.contracts.profile_release import ProfileReleaseCandidate
from itda.domain.canonical import canonical_json_bytes
from itda.pipeline.phase3_lane_baseline import project_phase3_lane_baseline

_MAX_INPUT_BYTES = 8_000_000
PENDING_PROTECTED_BASELINE_EXIT_CODE = 3
_AUTHORITY_ROOT = Path("/var/lib/itda/phase3-lane-authority")
_AUTHORITY_BUNDLE_FILENAME = "bundle.json"
_AUTHORITY_RECEIPT_FILENAME = "receipt.json"


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
    )


def _read_bounded_nofollow(path: Path) -> bytes:
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    nofollow_flag = getattr(os, "O_NOFOLLOW", 0)
    if not directory_flag or not nofollow_flag:
        raise OSError("secure lane baseline file flags are unavailable")
    if os.open not in os.supports_dir_fd or os.stat not in os.supports_dir_fd:
        raise OSError("descriptor-relative lane baseline reads are unavailable")
    directory_descriptor = os.open(
        path.parent,
        os.O_RDONLY | directory_flag | nofollow_flag,
    )
    try:
        directory_state = os.fstat(directory_descriptor)
        if not stat.S_ISDIR(directory_state.st_mode):
            raise ValueError("lane baseline input parent is invalid")
        before = os.stat(path.name, dir_fd=directory_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= _MAX_INPUT_BYTES
        ):
            raise ValueError("lane baseline input is not a bounded regular file")
        descriptor = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow_flag,
            dir_fd=directory_descriptor,
        )
        try:
            opened = os.fstat(descriptor)
            if _stat_identity(before) != _stat_identity(opened):
                raise ValueError("lane baseline input changed before open")
            chunks: list[bytes] = []
            remaining = opened.st_size
            while remaining:
                chunk = os.read(descriptor, min(remaining, 65_536))
                if not chunk:
                    raise ValueError("lane baseline input ended before its pinned size")
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(descriptor)
            if _stat_identity(opened) != _stat_identity(after):
                raise ValueError("lane baseline input changed during read")
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    finally:
        os.close(directory_descriptor)


def _load_canonical_mapping(path: Path) -> Mapping[str, Any]:
    raw = _read_bounded_nofollow(path)
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("lane baseline input is not canonical JSON") from exc
    if not isinstance(payload, dict) or raw != canonical_json_bytes(payload):
        raise ValueError("lane baseline input is not a canonical object")
    return payload


def _load_profile_bodies(path: Path) -> dict[str, bytes]:
    payload = _load_canonical_mapping(path)
    if set(payload) != {"schema_version", "profiles"}:
        raise ValueError("profile body bundle shape is invalid")
    if payload["schema_version"] != "itda.phase3-profile-bodies.v1":
        raise ValueError("profile body bundle version is invalid")
    profiles = payload["profiles"]
    if (
        isinstance(profiles, (str, bytes, bytearray))
        or not isinstance(profiles, Sequence)
        or len(profiles) != 24
    ):
        raise ValueError("profile body bundle requires exactly 24 profiles")
    bodies: dict[str, bytes] = {}
    for row in profiles:
        if not isinstance(row, Mapping) or set(row) != {"place_ref", "profile"}:
            raise ValueError("profile body bundle member shape is invalid")
        place_ref = row["place_ref"]
        profile = row["profile"]
        if not isinstance(place_ref, str) or not isinstance(profile, Mapping):
            raise ValueError("profile body bundle member is invalid")
        if place_ref in bodies:
            raise ValueError("profile body bundle contains duplicate members")
        bodies[place_ref] = canonical_json_bytes(profile)
    return bodies


def _write_no_replace(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    nofollow_flag = getattr(os, "O_NOFOLLOW", 0)
    if not directory_flag or not nofollow_flag or os.open not in os.supports_dir_fd:
        raise OSError("secure lane baseline publication is unavailable")
    directory_descriptor = os.open(
        path.parent,
        os.O_RDONLY | directory_flag | nofollow_flag,
    )
    try:
        descriptor = os.open(
            path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow_flag,
            0o600,
            dir_fd=directory_descriptor,
        )
        try:
            written = 0
            while written < len(payload):
                written += os.write(descriptor, payload[written:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--profiles", type=Path, required=True)
    parser.add_argument("--active-release-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    release_raw = _read_bounded_nofollow(args.release)
    release = ProfileReleaseCandidate.model_validate_json(release_raw)
    if release_raw != canonical_json_bytes(release.model_dump(mode="json")):
        raise ValueError("predecessor release input is not canonical")
    bundle_path = _AUTHORITY_ROOT / _AUTHORITY_BUNDLE_FILENAME
    receipt_path = _AUTHORITY_ROOT / _AUTHORITY_RECEIPT_FILENAME
    if not bundle_path.exists() and not receipt_path.exists():
        authority = None
        trusted_authority_sha256 = None
    else:
        if not bundle_path.exists() or not receipt_path.exists():
            raise ValueError("phase 3 lane authority store is incomplete")
        authority = Phase3LaneAuthorityBundle.model_validate(
            _load_canonical_mapping(bundle_path)
        )
        receipt = _load_canonical_mapping(receipt_path)
        if set(receipt) != {"schema_version", "authority_sha256"} or receipt.get(
            "schema_version"
        ) != "itda.phase3-lane-authority-receipt.v1":
            raise ValueError("phase 3 lane authority receipt is invalid")
        trusted_authority_sha256 = receipt.get("authority_sha256")
        if not isinstance(trusted_authority_sha256, str):
            raise ValueError("phase 3 lane authority receipt digest is invalid")
    result = project_phase3_lane_baseline(
        predecessor_release=release,
        active_release_sha256=args.active_release_sha256,
        profile_bodies=_load_profile_bodies(args.profiles),
        authority_bundle=authority,
        trusted_authority_sha256=trusted_authority_sha256,
    )
    _write_no_replace(
        args.output,
        canonical_json_bytes(result.model_dump(mode="json")),
    )
    if result.status == "PENDING_PROTECTED_BASELINE":
        return PENDING_PROTECTED_BASELINE_EXIT_CODE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
