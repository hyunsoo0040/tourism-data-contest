"""Canonical JSON bytes and digest helpers for integrity artifacts."""

from __future__ import annotations

import hashlib
import json


def canonical_json_bytes(payload: object) -> bytes:
    """Encode JSON with stable UTF-8, key ordering, and no insignificant whitespace."""

    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(payload: object) -> str:
    """Return the lower-case SHA-256 digest of canonical JSON bytes."""

    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
