"""Build provider-free synthetic artifacts for the Phase 4 DVC reproducibility DAG."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path

from itda.domain.canonical import canonical_json_bytes, canonical_sha256

DAG_STAGE_ORDER = ("select", "observe", "evaluate", "fuse", "export")
ARTIFACT_SCHEMA_VERSION = "itda.phase4-dag-artifact.v1"
_STAGE_INPUTS = {
    "select": ("challenge-pack.json", "dag-seed.json"),
    "observe": (
        "challenge-pack.json",
        "dag-seed.json",
        "provider-replay.json",
        "selection.json",
    ),
    "evaluate": (
        "challenge-pack.json",
        "dag-seed.json",
        "observations.json",
        "provider-replay.json",
        "selection.json",
    ),
    "fuse": (
        "benchmark.json",
        "challenge-pack.json",
        "dag-seed.json",
        "observations.json",
        "provider-replay.json",
        "selection.json",
    ),
    "export": (
        "benchmark.json",
        "challenge-pack.json",
        "dag-seed.json",
        "fusion.json",
        "observations.json",
        "provider-replay.json",
        "selection.json",
    ),
}
_PREDECESSOR = {
    "observe": ("selection.json", "select"),
    "evaluate": ("observations.json", "observe"),
    "fuse": ("benchmark.json", "evaluate"),
    "export": ("fusion.json", "fuse"),
}
_MAX_INPUT_BYTES = 32 * 1024 * 1024
_PROHIBITED_KEYS = {
    "api_key",
    "authorization",
    "bigmodel_api_key",
    "blind_members",
    "canonical_place_ids",
    "catalog_members",
    "dev_label_scores",
    "dev_members",
    "expert_label",
    "expert_labels",
    "members",
    "ordered_catalog_ids",
    "protected_path",
    "raw_image_bytes",
    "raw_provider_body",
    "raw_response_body",
    "reconciliation_nonce",
    "service_key",
    "zhipuai_api_key",
}
_SECRET_PATTERNS = (
    re.compile(rb"postgres(?:ql)?://[^\s]+", re.IGNORECASE),
    re.compile(rb"\b(?:service[_-]?key|password|secret)\s*[:=]\s*[^\s,}]+", re.IGNORECASE),
    re.compile(rb"\b(?:sk|ak)-[A-Za-z0-9_-]{16,}"),
)
_IMAGE_SUFFIXES = {".avif", ".bmp", ".gif", ".heic", ".jpeg", ".jpg", ".png", ".webp"}


class ArtifactLeakageError(ValueError):
    """Raised when a public Phase 4 surface contains protected material."""


def _mapping_items(value: object) -> Sequence[tuple[str, object]]:
    if not isinstance(value, dict):
        return ()
    return tuple((str(key), nested) for key, nested in value.items())


def _scan_value(value: object) -> None:
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            for key, nested in _mapping_items(current):
                if key.casefold() in _PROHIBITED_KEYS:
                    raise ArtifactLeakageError("public artifact contains a protected key")
                stack.append(nested)
        elif isinstance(current, list):
            stack.extend(current)
        elif isinstance(current, str):
            lowered = current.casefold()
            if "/artifacts/restricted/" in lowered or "/protected/" in lowered:
                raise ArtifactLeakageError("public artifact contains a protected path")
            if lowered.startswith("place:"):
                raise ArtifactLeakageError("public artifact contains a protected place identity")


def assert_public_artifact_safe(path: Path, payload: bytes) -> None:
    """Reject secrets, protected identities/paths, raw media, and label authority."""

    if path.suffix.casefold() in _IMAGE_SUFFIXES:
        raise ArtifactLeakageError("public Phase 4 surfaces cannot contain image bytes")
    for pattern in _SECRET_PATTERNS:
        if pattern.search(payload):
            raise ArtifactLeakageError("public artifact contains a secret-shaped value")
    if path.suffix.casefold() == ".json":
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ArtifactLeakageError("public JSON artifact is malformed") from exc
        _scan_value(parsed)


def _safe_read(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= _MAX_INPUT_BYTES
        ):
            raise ValueError("DVC input must be a bounded single-link regular file")
        payload = bytearray()
        while len(payload) <= before.st_size:
            chunk = os.read(descriptor, min(64 * 1024, before.st_size + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        if len(payload) != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise OSError("DVC input changed while being read")
        result = bytes(payload)
        assert_public_artifact_safe(path, result)
        return result
    finally:
        os.close(descriptor)


def load_phase4_params(path: Path) -> dict[str, int | str]:
    """Parse the deliberately flat Phase 4 params mapping without YAML code execution."""

    payload = _safe_read(path).decode("utf-8")
    lines = [
        line for line in payload.splitlines() if line.strip() and not line.lstrip().startswith("#")
    ]
    if not lines or lines[0] != "phase4:":
        raise ValueError("params.yaml must contain one phase4 mapping")
    result: dict[str, int | str] = {}
    for line in lines[1:]:
        if not line.startswith("  ") or line.startswith("    "):
            raise ValueError("Phase 4 params must be a flat two-space mapping")
        key, separator, raw_value = line.strip().partition(": ")
        if not separator or not re.fullmatch(r"[a-z][a-z0-9_]*", key):
            raise ValueError("Phase 4 params contain a malformed key")
        value: int | str = int(raw_value) if raw_value.isdecimal() else raw_value
        if key in result:
            raise ValueError("Phase 4 params contain a duplicate key")
        result[key] = value
    required = {
        "challenge_pack_sha256",
        "config_revision",
        "fusion_policy_sha256",
        "output_schema_version",
        "provider_replay_sha256",
        "random_seed",
    }
    if set(result) != required:
        raise ValueError("Phase 4 params do not have the exact approved key set")
    if result["output_schema_version"] != ARTIFACT_SCHEMA_VERSION:
        raise ValueError("Phase 4 output schema version is not approved")
    return result


def _validated_json(name: str, payload: bytes) -> dict[str, object]:
    parsed = json.loads(payload)
    if not isinstance(parsed, dict):
        raise ValueError("DVC JSON input must be an object")
    canonical = canonical_json_bytes(parsed)
    if payload not in {canonical, canonical + b"\n"}:
        raise ValueError("DVC JSON input must use canonical bytes")
    self_field = {
        "challenge-pack.json": "pack_sha256",
        "provider-replay.json": "fixture_sha256",
        "dag-seed.json": "seed_sha256",
    }.get(name, "artifact_sha256")
    claimed = parsed.get(self_field)
    if claimed != canonical_sha256(
        {key: value for key, value in parsed.items() if key != self_field}
    ):
        raise ValueError("DVC JSON input self-digest is stale")
    return parsed


def _validate_predecessor_artifact(
    parent: Mapping[str, object],
    *,
    predecessor_stage: str,
    params_sha256: str,
    loaded: Mapping[str, bytes],
    expected_details: Mapping[str, object],
) -> None:
    details = parent.get("details")
    input_digests = parent.get("input_digests")
    if not isinstance(details, dict) or not isinstance(input_digests, list):
        raise ValueError("DVC predecessor details or inputs are invalid")
    if details != expected_details:
        raise ValueError("DVC predecessor details are not the typed stage result")
    expected_input_digests = [
        {"input_id": name, "sha256": _sha256(loaded[name])}
        for name in _STAGE_INPUTS[predecessor_stage]
    ]
    if input_digests != expected_input_digests:
        raise ValueError("DVC predecessor input inventory is invalid")
    if parent.get("params_sha256") != params_sha256:
        raise ValueError("DVC predecessor parameter root is stale")


def _derived_stage_details(
    stage: str,
    *,
    parsed_json: Mapping[str, Mapping[str, object]],
    loaded: Mapping[str, bytes],
    params: Mapping[str, int | str],
) -> dict[str, object]:
    if stage == "select":
        challenge = parsed_json["challenge-pack.json"]
        seed = parsed_json["dag-seed.json"]
        if challenge["pack_sha256"] != params["challenge_pack_sha256"]:
            raise ValueError("challenge pack does not match the frozen Phase 4 params")
        if (
            seed.get("challenge_pack_file_sha256") != _sha256(loaded["challenge-pack.json"])
            or seed.get("fusion_policy_sha256") != params["fusion_policy_sha256"]
        ):
            raise ValueError("DAG seed does not bind the challenge pack and fusion policy")
        cases = challenge["cases"]
        if not isinstance(cases, list) or any(not isinstance(case, dict) for case in cases):
            raise ValueError("challenge pack cases are not a typed inventory")
        return {
            "case_count": len(cases),
            "scenario_inventory_sha256": canonical_sha256(
                sorted(str(case["scenario"]) for case in cases)
            ),
            "selection_state": "SYNTHETIC_SELECTION_FROZEN",
        }
    if stage == "observe":
        replay = parsed_json["provider-replay.json"]
        seed = parsed_json["dag-seed.json"]
        if replay["fixture_sha256"] != params["provider_replay_sha256"]:
            raise ValueError("provider replay does not match the frozen Phase 4 params")
        if seed.get("provider_replay_file_sha256") != _sha256(
            loaded["provider-replay.json"]
        ):
            raise ValueError("DAG seed does not bind the provider replay bytes")
        return {
            "provider_fixture_sha256": replay["fixture_sha256"],
            "provider_mode": "OFFLINE_REPLAY_ONLY",
            "observation_state": "SYNTHETIC_OBSERVATIONS_FROZEN",
        }
    if stage == "evaluate":
        return {
            "evaluator_implementation": "itda.cli.evaluate_phase4",
            "report_state": "NOT_EXECUTED_NO_BENCHMARK_AUTHORITY",
            "predecessor_state": "SYNTHETIC_OBSERVATIONS_VALIDATED",
            "external_evidence_state": "PENDING_EXTERNAL_EVIDENCE",
        }
    if stage == "fuse":
        seed = parsed_json["dag-seed.json"]
        if seed["fusion_policy_sha256"] != params["fusion_policy_sha256"]:
            raise ValueError("fusion policy does not match the frozen Phase 4 params")
        return {
            "fusion_state": "NOT_EXECUTED_NO_PHASE3_LANE_BASELINE",
            "predecessor_state": "SYNTHETIC_EVALUATION_LINEAGE_VALIDATED",
            "release_eligible": False,
        }
    return {
        "export_state": "LINEAGE_VALIDATED_NOT_A_RELEASE_EXPORT",
        "predecessor_state": "SYNTHETIC_FUSION_LINEAGE_VALIDATED",
        "external_evidence": [
            "PENDING_PROTECTED_MATERIALIZATION",
            "PENDING_PROVIDER_CALL",
            "PENDING_HUMAN_REVIEW",
            "PENDING_RELEASE_ACTION",
        ],
        "release_eligible": False,
    }


def _stage_details(
    stage: str,
    inputs: tuple[tuple[str, bytes], ...],
    params: Mapping[str, int | str],
) -> dict[str, object]:
    names = tuple(sorted(name for name, _ in inputs))
    if names != _STAGE_INPUTS[stage]:
        raise ValueError("DVC stage input inventory differs from the frozen DAG")
    loaded = dict(inputs)
    parsed_json = {
        name: _validated_json(name, payload) for name, payload in inputs if name.endswith(".json")
    }
    params_sha256 = canonical_sha256(dict(sorted(params.items())))
    predecessor = _PREDECESSOR.get(stage)
    if predecessor is not None:
        predecessor_name, predecessor_stage = predecessor
        parent = parsed_json[predecessor_name]
        if (
            set(parent)
            != {
                "artifact_schema_version",
                "artifact_sha256",
                "authority",
                "details",
                "input_digests",
                "offline",
                "params_sha256",
                "release_eligible",
                "stage",
            }
            or parent.get("artifact_schema_version") != ARTIFACT_SCHEMA_VERSION
            or parent.get("authority") != "REPRODUCIBILITY_ONLY"
            or parent.get("offline") is not True
            or parent.get("release_eligible") is not False
            or parent.get("params_sha256") != params_sha256
            or parent.get("stage") != predecessor_stage
        ):
            raise ValueError("DVC predecessor stage, schema, or authority is invalid")
        _validate_predecessor_artifact(
            parent,
            predecessor_stage=predecessor_stage,
            params_sha256=params_sha256,
            loaded=loaded,
            expected_details=_derived_stage_details(
                predecessor_stage,
                parsed_json=parsed_json,
                loaded=loaded,
                params=params,
            ),
        )
    return _derived_stage_details(
        stage,
        parsed_json=parsed_json,
        loaded=loaded,
        params=params,
    )


def run_stage(
    *,
    stage: str,
    inputs: Sequence[Path],
    params: Mapping[str, int | str],
    output: Path,
) -> dict[str, object]:
    """Create one canonical, no-replace, authority-free synthetic stage artifact."""

    if stage not in DAG_STAGE_ORDER:
        raise ValueError("unknown or unauthorized offline artifact stage")
    if not inputs:
        raise ValueError("offline artifact stage requires at least one immutable input")
    if os.environ.get("ITDA_OFFLINE") != "1":
        raise ValueError("offline artifact stage requires ITDA_OFFLINE=1")

    loaded = tuple((path.name, _safe_read(path)) for path in inputs)
    input_digests = [
        {"input_id": name, "sha256": _sha256(payload)} for name, payload in sorted(loaded)
    ]
    fields: dict[str, object] = {
        "artifact_schema_version": ARTIFACT_SCHEMA_VERSION,
        "authority": "REPRODUCIBILITY_ONLY",
        "details": _stage_details(stage, loaded, params),
        "input_digests": input_digests,
        "offline": True,
        "params_sha256": canonical_sha256(dict(sorted(params.items()))),
        "release_eligible": False,
        "stage": stage,
    }
    artifact = {**fields, "artifact_sha256": canonical_sha256(fields)}
    encoded = canonical_json_bytes(artifact)
    assert_public_artifact_safe(output, encoded)
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        output,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        written = 0
        while written < len(encoded):
            written += os.write(descriptor, encoded[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return artifact


def _sha256(payload: bytes) -> str:
    import hashlib

    return hashlib.sha256(payload).hexdigest()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", required=True, choices=DAG_STAGE_ORDER)
    parser.add_argument("--input", action="append", required=True, type=Path)
    parser.add_argument("--params", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    run_stage(
        stage=args.stage,
        inputs=tuple(args.input),
        params=load_phase4_params(args.params),
        output=args.output,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
