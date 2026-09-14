"""Lossless recovery of a single complete JSON answer followed by non-JSON prose."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from itda.authenticity.batch import write_once
from itda.authenticity.contracts import TextWire
from itda.authenticity.model import MODEL
from itda.authenticity.rubric import FACET_KEYS
from itda.domain.canonical import canonical_sha256


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("AMBIGUOUS_DUPLICATED_JSON_KEY")
        result[key] = value
    return result


def extract(
    record: dict[str, Any], *, allow_facet_rejections: bool = False
) -> tuple[dict[str, Any], dict[str, Any]]:
    if record["record_sha256"] != canonical_sha256(
        {k: v for k, v in record.items() if k != "record_sha256"}
    ):
        raise ValueError("RECOVERED_MODEL_RECORD_CHANGED")
    if hashlib.sha256(record["raw_response"].encode()).hexdigest() != record["response_sha256"]:
        raise ValueError("RECOVERED_MODEL_RESPONSE_CHANGED")
    if (
        record["http_status"] != 200
        or canonical_sha256(record["request"]) != record["request_sha256"]
    ):
        raise ValueError("RECOVERED_MODEL_REQUEST_CHANGED")
    envelope = json.loads(record["raw_response"])
    if envelope.get("model") != MODEL or len(envelope.get("choices", [])) != 1:
        raise ValueError("RECOVERED_MODEL_IDENTITY_CHANGED")
    choice = envelope["choices"][0]
    if choice.get("finish_reason") != "stop" or choice.get("message", {}).get("tool_calls"):
        raise ValueError("RECOVERED_MODEL_RESPONSE_INCOMPLETE")
    content = choice["message"]["content"]
    if not isinstance(content, str):
        raise ValueError("RECOVERED_CONTENT_NOT_TEXT")
    leading = content.lstrip()
    start = len(content) - len(leading)
    if not leading.startswith("{"):
        raise ValueError("NO_LEADING_JSON_OBJECT")
    wire, end = json.JSONDecoder(object_pairs_hook=_unique).raw_decode(leading)
    suffix = leading[end:]
    if not suffix.strip() or any(c in suffix for c in "{}[]"):
        raise ValueError("AMBIGUOUS_OR_ABSENT_UNSTRUCTURED_SUFFIX")
    if not isinstance(wire, dict) or set(wire) != {"judgments"}:
        raise ValueError("RECOVERED_ENVELOPE_INVALID")
    rows = wire["judgments"]
    if (
        not isinstance(rows, list)
        or not all(isinstance(row, dict) and isinstance(row.get("key"), str) for row in rows)
        or sorted(row["key"] for row in rows) != sorted(FACET_KEYS)
    ):
        raise ValueError("RECOVERED_FACET_MEMBERSHIP_INVALID")
    if not allow_facet_rejections:
        TextWire.model_validate(wire)
    return wire, {
        "method": (
            "LEADING_COMPLETE_JSON_FACET_VALIDATION_DEFERRED_TO_BINDER"
            if allow_facet_rejections
            else "LEADING_COMPLETE_JSON_UNSTRUCTURED_SUFFIX_RETAINED"
        ),
        "json_char_start": start,
        "json_char_end": start + end,
        "json_text_sha256": hashlib.sha256(leading[:end].encode()).hexdigest(),
        "suffix_sha256": hashlib.sha256(suffix.encode()).hexdigest(),
        "suffix_characters": len(suffix),
        "values_rewritten": False,
    }


def from_attempts(
    directory: Path, request_sha: str
) -> tuple[dict[str, Any], dict[str, Any], Path] | None:
    # Preserve v1 selection priority. Only if no whole-schema response exists,
    # recover the same complete envelope for the frozen per-facet binder. It
    # rejects invalid facets and retains their original proposals verbatim.
    return _from_attempts(directory, request_sha, allow_facet_rejections=False) or _from_attempts(
        directory, request_sha, allow_facet_rejections=True
    )


def _from_attempts(
    directory: Path, request_sha: str, *, allow_facet_rejections: bool
) -> tuple[dict[str, Any], dict[str, Any], Path] | None:
    candidates = []
    for folder in ("attempt-1", "attempt-2"):
        for path in (directory / "model-cache" / folder).glob(request_sha + "-*.attempt.json"):
            record = json.loads(path.read_text())
            if record["record_sha256"] != canonical_sha256(
                {k: v for k, v in record.items() if k != "record_sha256"}
            ):
                raise ValueError("RECOVERY_ATTEMPT_RECORD_CHANGED")
            if (
                hashlib.sha256(record["raw_response"].encode()).hexdigest()
                != record["response_sha256"]
            ):
                raise ValueError("RECOVERY_ATTEMPT_RESPONSE_CHANGED")
            try:
                wire, metadata = extract(record, allow_facet_rejections=allow_facet_rejections)
            except (ValueError, KeyError, TypeError):
                continue
            if record["request_sha256"] != request_sha:
                raise ValueError("RECOVERY_REQUEST_IDENTITY_MISMATCH")
            candidates.append((record["retrieved_at"], path, record, wire, metadata))
    if not candidates:
        return None
    _, path, record, wire, metadata = min(candidates, key=lambda c: c[0])
    payload = {
        "version": (
            "authenticity-lossless-wire-recovery-v2"
            if allow_facet_rejections
            else "authenticity-lossless-wire-recovery-v1"
        ),
        "model_record_path": str(path),
        "model_record_sha256": record["record_sha256"],
        "request_sha256": request_sha,
        "wire": wire,
        "extraction": metadata,
    }
    payload["recovery_sha256"] = canonical_sha256(payload)
    saved = directory / "format-recovery/wires" / (payload["recovery_sha256"] + ".json")
    write_once(saved, payload)
    meta = {
        "request_sha256": request_sha,
        "record_path": str(path),
        "record_sha256": record["record_sha256"],
        "response_sha256": record["response_sha256"],
        "retrieved_at": record["retrieved_at"],
        "parse_method": metadata["method"],
        "cached": True,
    }
    return wire, meta, saved


def load(path: Path, request_sha: str) -> dict[str, Any]:
    payload = json.loads(path.read_text())
    if payload["recovery_sha256"] != canonical_sha256(
        {k: v for k, v in payload.items() if k != "recovery_sha256"}
    ):
        raise ValueError("WIRE_RECOVERY_ARTIFACT_CHANGED")
    record = json.loads(Path(payload["model_record_path"]).read_text())
    if payload.get("version") not in {
        "authenticity-lossless-wire-recovery-v1",
        "authenticity-lossless-wire-recovery-v2",
    }:
        raise ValueError("WIRE_RECOVERY_VERSION_UNSUPPORTED")
    wire, metadata = extract(
        record,
        allow_facet_rejections=payload["version"] == "authenticity-lossless-wire-recovery-v2",
    )
    if (
        wire != payload["wire"]
        or metadata != payload["extraction"]
        or request_sha != payload["request_sha256"]
        or record["request_sha256"] != request_sha
        or record["record_sha256"] != payload["model_record_sha256"]
    ):
        raise ValueError("WIRE_RECOVERY_REPLAY_DIFFERS")
    return wire
