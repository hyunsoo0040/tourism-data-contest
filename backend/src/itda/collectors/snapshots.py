"""Append-only serialization for sanitized provider collection results."""

from __future__ import annotations

import os
from pathlib import Path

from itda.collectors.base import CollectedResponse


def write_snapshot(collected: CollectedResponse, output_directory: Path) -> Path:
    """Create one immutable snapshot; an existing digest path is never overwritten."""

    output_directory.mkdir(parents=True, exist_ok=True)
    operation = collected.endpoint.rsplit("/", maxsplit=1)[-1]
    path = output_directory / (
        f"{collected.provider}-{operation}-{collected.raw_response_sha256}.json"
    )
    payload = collected.to_json_bytes()
    with path.open("xb") as snapshot_file:
        snapshot_file.write(payload)
        snapshot_file.flush()
        os.fsync(snapshot_file.fileno())
    return path


def write_snapshot_for_resume(
    collected: CollectedResponse,
    output_directory: Path,
) -> Path:
    """Create a success snapshot once or accept only an exact existing snapshot."""

    try:
        return write_snapshot(collected, output_directory)
    except FileExistsError:
        operation = collected.endpoint.rsplit("/", maxsplit=1)[-1]
        path = output_directory / (
            f"{collected.provider}-{operation}-{collected.raw_response_sha256}.json"
        )
        expected = collected.to_json_bytes()
        try:
            metadata = path.lstat()
            if path.is_symlink() or not path.is_file() or metadata.st_nlink != 1:
                raise FileExistsError("existing snapshot path is not a regular single-link file")
            if path.read_bytes() != expected:
                raise FileExistsError("existing snapshot bytes do not match immutable response")
        except OSError as exc:
            raise FileExistsError("existing snapshot could not be verified") from exc
        return path
