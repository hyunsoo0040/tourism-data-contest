"""Replay sealed Phase 2 evidence into a traffic-free optional-media-v2 projection."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from itda.cli.audit_catalog_readiness import build_kto_recovery_readiness
from itda.contracts.catalog_optional_media import (
    ImageMediumState,
    OptionalMediaCandidateSet,
    OptionalMediaPolicyV2,
    OptionalMediaProjection,
    build_optional_media_policy,
    project_optional_media_candidate,
    verify_historical_lineage,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

HISTORICAL_TERMINAL_ROOT = "fab840841288cc0b0e1b31454cf65de5679e5cda0326a57ce42f22d0bdf377ac"
HISTORICAL_TERMINAL_HISTORY_SHA256 = (
    "20490fa01d86f3653dc29fe9832fdd1da5e0d47af6861c595b2492b64054a058"
)
HISTORICAL_TERMINAL_HISTORY_SIZE = 30_192
TERMINAL_HISTORY_REL = Path(
    ".planning/phases/02-canonical-36-rights-and-evaluation-manifest/02-49-TERMINAL-HISTORY.md"
)
TERMINAL_FAILURE_REL = Path(
    "artifacts/restricted/catalog/v2/supplemental/kto-recovery/reentries/"
    f"{HISTORICAL_TERMINAL_ROOT}/reentry-exhausted.json"
)
AGGREGATE_REL = Path(
    "artifacts/restricted/catalog/v2/enrichment/rounds/"
    "01072d20529d6114c0b1d7093f02b42f547e9f519fadc6b09e838c1c2a969b55/"
    "aggregate-readiness.json"
)
NORMALIZATION_ROOT = "540bdc90c709418fe690956e56e3b50b402d0ba7e16b4c4c417fdc27a5389b10"
NORMALIZATION_REL = Path(
    "artifacts/restricted/catalog/v2/supplemental/kto-recovery/normalizations/"
    f"{NORMALIZATION_ROOT}/normalization.json"
)
ELIGIBILITY_ROOT = "e8fb691be0715b149a4cd9d9601aac76a90a42827a0c7c6367fa3a7261af97d0"
REQUEST_MANIFEST_REL = Path(
    "artifacts/restricted/catalog/v2/supplemental/kto-recovery/eligibility/"
    f"{ELIGIBILITY_ROOT}/request-manifest.json"
)
PREFLIGHT_ROOT = "821b05517a1908526e95a3e6c445017888538ae5d24fac223682bf4a59768777"
PREFLIGHT_REL = Path(
    "artifacts/restricted/catalog/v2/supplemental/kto-recovery/preflight-readiness/"
    f"{PREFLIGHT_ROOT}/preflight-readiness.json"
)
ENTITY_PROJECTION_REL = Path("artifacts/restricted/catalog/v2/projection/entity-projection.json")
OUTPUT_BASE_REL = Path("artifacts/catalog/optional-media-v2/policy")
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_UNIVERSE_ROWS = 1_000


class OptionalMediaReplayError(ValueError):
    """Named fail-closed replay error."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _assert_nofollow_ancestors(path: Path) -> None:
    current = path.parent
    while current != current.parent:
        if current.is_symlink():
            raise OptionalMediaReplayError(f"symlink ancestor is forbidden: {current}")
        current = current.parent


def _read_regular_bytes_nofollow(path: Path, *, max_bytes: int) -> bytes:
    _assert_nofollow_ancestors(path)
    try:
        before = path.lstat()
    except FileNotFoundError as exc:
        raise OptionalMediaReplayError(f"required evidence is missing: {path}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise OptionalMediaReplayError(f"evidence must be a regular non-symlink file: {path}")
    if before.st_size > max_bytes:
        raise OptionalMediaReplayError(f"evidence exceeds size bound: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            or before.st_size != opened.st_size
        ):
            raise OptionalMediaReplayError("evidence identity changed during no-follow open")
        payload = b""
        while len(payload) < opened.st_size:
            chunk = os.read(descriptor, min(1_048_576, opened.st_size - len(payload)))
            if not chunk:
                break
            payload += chunk
        if len(payload) != opened.st_size:
            raise OptionalMediaReplayError("short read while loading sealed evidence")
        after = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            raise OptionalMediaReplayError("evidence identity changed during read")
        return payload
    finally:
        os.close(descriptor)


def load_canonical_json_nofollow(
    path: Path | str,
    *,
    max_bytes: int = MAX_JSON_BYTES,
) -> dict[str, object]:
    """Load one bounded canonical JSON object without following a substituted file."""

    target = Path(path)
    raw = _read_regular_bytes_nofollow(target, max_bytes=max_bytes)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OptionalMediaReplayError("sealed evidence is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise OptionalMediaReplayError("sealed evidence must be a JSON object")
    if canonical_json_bytes(value) != raw:
        raise OptionalMediaReplayError("sealed evidence is not canonical JSON")
    return value


def _validated_aggregate(aggregate: Mapping[str, object]) -> list[Mapping[str, object]]:
    unsigned = dict(aggregate)
    recorded_sha256 = unsigned.pop("aggregate_sha256", None)
    if aggregate.get(
        "schema_version"
    ) != "itda.catalog-aggregate-readiness.v1" or recorded_sha256 != canonical_sha256(unsigned):
        raise OptionalMediaReplayError("aggregate readiness digest drifted")
    rows_value = aggregate.get("rows")
    if (
        not isinstance(rows_value, list)
        or not 1 <= len(rows_value) <= MAX_UNIVERSE_ROWS
        or not all(isinstance(row, Mapping) for row in rows_value)
    ):
        raise OptionalMediaReplayError("sealed universe row inventory is invalid")
    rows = list(rows_value)
    ids = [row.get("place_entity_id") for row in rows]
    if (
        any(not isinstance(value, str) for value in ids)
        or len(set(ids)) != len(ids)
        or ids != sorted(ids)
    ):
        raise OptionalMediaReplayError(
            "sealed universe requires unique canonical place identity order"
        )
    return rows


def _validated_responses(
    normalization: Mapping[str, object],
) -> dict[str, dict[str, Mapping[str, object]]]:
    responses_value = normalization.get("responses")
    if (
        normalization.get("schema_version") != "itda.kto-recovery-normalization.v1"
        or normalization.get("status") != "SUCCESS"
        or normalization.get("response_count") != 48
        or not isinstance(responses_value, list)
        or len(responses_value) != 48
        or not all(isinstance(row, Mapping) for row in responses_value)
    ):
        raise OptionalMediaReplayError("KTO normalization inventory drifted")
    by_candidate: dict[str, dict[str, Mapping[str, object]]] = {}
    request_ids: set[str] = set()
    for row in responses_value:
        candidate_id = row.get("provider_candidate_id")
        operation = row.get("operation")
        request_identity = row.get("request_identity")
        if (
            not isinstance(candidate_id, str)
            or operation not in {"detailCommon2", "detailImage2"}
            or not isinstance(request_identity, str)
            or request_identity in request_ids
            or operation in by_candidate.setdefault(candidate_id, {})
        ):
            raise OptionalMediaReplayError("KTO normalized response identity is invalid")
        request_ids.add(request_identity)
        by_candidate[candidate_id][str(operation)] = row
    if len(by_candidate) != 24 or any(
        set(pair) != {"detailCommon2", "detailImage2"} for pair in by_candidate.values()
    ):
        raise OptionalMediaReplayError("KTO normalization must contain 24 exact pairs")
    return by_candidate


def _image_state(
    direct_media_state: object,
    asset_rights: Mapping[str, object],
) -> ImageMediumState:
    reason = str(asset_rights.get("reason", ""))
    if direct_media_state == "PASS":
        return ImageMediumState.QUALIFIED
    if direct_media_state == "MISSING":
        return ImageMediumState.EMPTY if "SUCCESS_EMPTY" in reason else ImageMediumState.MISSING
    if direct_media_state == "ANALYSIS_FAILED":
        return ImageMediumState.ANALYSIS_FAILED
    if "PROVENANCE" in reason:
        return ImageMediumState.PROVENANCE_INCOMPLETE
    return ImageMediumState.RIGHTS_RESTRICTED


def _historical_row(
    source_row: Mapping[str, object],
    response_pair: Mapping[str, Mapping[str, object]] | None,
) -> dict[str, object]:
    gates = source_row.get("objective_gate_states")
    if not isinstance(gates, Mapping):
        raise OptionalMediaReplayError("source row lacks objective gate leaves")
    source_sha256 = source_row.get("row_sha256")
    if not isinstance(source_sha256, str):
        raise OptionalMediaReplayError("source row lacks exact evidence digest")
    if response_pair is None:
        direct_media_state = gates.get("direct_media")
        state = _image_state(
            direct_media_state,
            {
                "reason": (
                    "SOURCE_DIRECT_MEDIA_QUALIFIED"
                    if direct_media_state == "PASS"
                    else "SOURCE_DIRECT_MEDIA_MISSING"
                )
            },
        )
        qualified = state is ImageMediumState.QUALIFIED
        return {
            "place_entity_id": source_row.get("place_entity_id"),
            "identity_state": "PASS",
            "coordinates_state": gates.get("coordinates"),
            "description_state": gates.get("description"),
            "operating_info_state": gates.get("operating_info"),
            "dataset_rights": {
                "state": gates.get("dataset_rights"),
                "attestation_sha256": source_sha256,
            },
            "direct_media_state": direct_media_state,
            "image_medium_state": state.value,
            "asset_rights": {
                "state": "PASS" if qualified else "MISSING",
                "reason": (
                    "SOURCE_DIRECT_MEDIA_QUALIFIED" if qualified else "SOURCE_DIRECT_MEDIA_MISSING"
                ),
                "provenance_complete": qualified,
                "analysis_eligible": qualified,
                "ui_eligible": qualified,
                "demo_eligible": qualified,
                "attestation_sha256": source_sha256,
            },
            "response_evidence_sha256": source_sha256,
        }
    common = response_pair["detailCommon2"]
    image = response_pair["detailImage2"]
    if common.get("place_entity_id") != source_row.get("place_entity_id") or image.get(
        "place_entity_id"
    ) != source_row.get("place_entity_id"):
        raise OptionalMediaReplayError("KTO response pair is detached from source identity")
    dataset_rights = common.get("dataset_rights")
    asset_rights_value = image.get("asset_rights")
    if not isinstance(dataset_rights, Mapping) or not isinstance(asset_rights_value, Mapping):
        raise OptionalMediaReplayError("KTO response pair lacks separate rights lanes")
    asset_rights = dict(asset_rights_value)
    state = _image_state(image.get("direct_media_state"), asset_rights)
    qualified = state is ImageMediumState.QUALIFIED
    asset_rights["provenance_complete"] = state not in {
        ImageMediumState.MISSING,
        ImageMediumState.EMPTY,
        ImageMediumState.PROVENANCE_INCOMPLETE,
    }
    if qualified and not all(
        asset_rights.get(name) is True
        for name in ("analysis_eligible", "ui_eligible", "demo_eligible")
    ):
        raise OptionalMediaReplayError("qualified KTO image lacks all downstream lanes")
    return {
        "place_entity_id": source_row.get("place_entity_id"),
        "identity_state": "PASS",
        "coordinates_state": common.get("coordinates_state"),
        "description_state": common.get("description_state"),
        "operating_info_state": gates.get("operating_info"),
        "dataset_rights": dict(dataset_rights),
        "direct_media_state": image.get("direct_media_state"),
        "image_medium_state": state.value,
        "asset_rights": asset_rights,
        "response_evidence_sha256": image.get("response_evidence_sha256"),
    }


def project_sealed_universe(
    *,
    aggregate: Mapping[str, object],
    normalization: Mapping[str, object],
    policy: OptionalMediaPolicyV2,
) -> OptionalMediaCandidateSet:
    """Project every sealed source-neutral row exactly once under optional-media-v2."""

    policy = OptionalMediaPolicyV2.from_manifest(policy.model_dump(mode="json"))
    rows = _validated_aggregate(aggregate)
    responses = _validated_responses(normalization)
    source_candidates = {
        row.get("provider_place_candidate_id")
        for row in rows
        if isinstance(row.get("provider_place_candidate_id"), str)
    }
    if not set(responses).issubset(source_candidates):
        raise OptionalMediaReplayError("KTO normalization escapes the sealed universe")
    projected = tuple(
        sorted(
            (
                project_optional_media_candidate(
                    row,
                    _historical_row(
                        row,
                        responses.get(str(row.get("provider_place_candidate_id"))),
                    ),
                    policy,
                )
                for row in rows
            ),
            key=lambda candidate: candidate.place_entity_id,
        )
    )
    fields: dict[str, Any] = {
        "schema_version": "itda.catalog-optional-media-candidates.v2",
        "policy_version": policy.policy_version,
        "policy_sha256": policy.policy_sha256,
        "candidates": projected,
        "universe_count": len(projected),
        "catalog_eligible_count": sum(row.catalog_eligible for row in projected),
        "image_state_counts": {
            state.value: sum(row.image_medium.state is state for row in projected)
            for state in ImageMediumState
        },
        "candidates_root_sha256": canonical_sha256(
            [row.model_dump(mode="json") for row in projected]
        ),
    }
    digest_fields = {
        **fields,
        "candidates": [row.model_dump(mode="json") for row in projected],
    }
    return OptionalMediaCandidateSet(
        **fields,
        candidate_set_sha256=canonical_sha256(digest_fields),
    )


def _rebuilt_historical_parents(
    repository_root: Path,
) -> dict[str, str]:
    readiness = build_kto_recovery_readiness(repository_root)
    ancestry = readiness.preflight_payload.get("ancestry")
    if not isinstance(ancestry, dict):
        raise OptionalMediaReplayError("rebuilt Plan 49 readiness lacks ancestry")
    parents = {
        **ancestry,
        "decision_accounting_sha256": readiness.decision_accounting_sha256,
        "preflight_root_sha256": readiness.preflight_root_sha256,
        "reentry_disposition_root_sha256": readiness.reentry_root_sha256,
        "representation_quota_attestation_sha256": (
            readiness.representation_quota_attestation_sha256
        ),
        "substitution_root_sha256": readiness.substitution_root_sha256,
        "target_replay_sha256": readiness.target_replay_sha256,
        "universe_replay_sha256": readiness.universe_replay_sha256,
    }
    if any(not isinstance(value, str) for value in parents.values()):
        raise OptionalMediaReplayError("rebuilt Plan 49 parent digest is invalid")
    return dict(sorted(parents.items()))


def build_optional_media_projection(
    repository_root: Path | str,
) -> OptionalMediaProjection:
    """Verify D-26 and project the complete sealed universe without external effects."""

    root = Path(repository_root).resolve(strict=True)
    history_path = root / TERMINAL_HISTORY_REL
    history_bytes = _read_regular_bytes_nofollow(history_path, max_bytes=64 * 1024)
    if (
        len(history_bytes) != HISTORICAL_TERMINAL_HISTORY_SIZE
        or _sha256(history_bytes) != HISTORICAL_TERMINAL_HISTORY_SHA256
    ):
        raise OptionalMediaReplayError("historical Plan 49 terminal history drifted")
    terminal_path = root / TERMINAL_FAILURE_REL
    terminal = load_canonical_json_nofollow(terminal_path, max_bytes=64 * 1024)
    verify_historical_lineage(terminal, HISTORICAL_TERMINAL_ROOT)
    terminal_payload = terminal.get("payload")
    if not isinstance(terminal_payload, Mapping):
        raise OptionalMediaReplayError("historical terminal payload is invalid")
    cited_roots = terminal_payload.get("parents")
    if not isinstance(cited_roots, Mapping):
        raise OptionalMediaReplayError("historical terminal parents are invalid")
    rebuilt_parents = _rebuilt_historical_parents(root)
    if dict(sorted(cited_roots.items())) != rebuilt_parents:
        raise OptionalMediaReplayError("HISTORICAL_LINEAGE_DRIFT")

    aggregate_path = root / AGGREGATE_REL
    normalization_path = root / NORMALIZATION_REL
    aggregate = load_canonical_json_nofollow(aggregate_path)
    normalization_envelope = load_canonical_json_nofollow(normalization_path)
    if normalization_envelope.get(
        "normalization_root_sha256"
    ) != NORMALIZATION_ROOT or not isinstance(normalization_envelope.get("payload"), Mapping):
        raise OptionalMediaReplayError("normalization root envelope drifted")
    normalization = normalization_envelope["payload"]
    assert isinstance(normalization, Mapping)
    policy = build_optional_media_policy()
    candidate_set = project_sealed_universe(
        aggregate=aggregate,
        normalization=normalization,
        policy=policy,
    )

    evidence_paths = (
        TERMINAL_HISTORY_REL,
        TERMINAL_FAILURE_REL,
        AGGREGATE_REL,
        NORMALIZATION_REL,
        REQUEST_MANIFEST_REL,
        PREFLIGHT_REL,
        ENTITY_PROJECTION_REL,
    )
    source_files: dict[str, str] = {}
    for relpath in sorted(evidence_paths, key=lambda value: value.as_posix()):
        path = root / relpath
        source_files[relpath.as_posix()] = _sha256(
            _read_regular_bytes_nofollow(path, max_bytes=MAX_JSON_BYTES)
        )
    fields: dict[str, Any] = {
        "schema_version": "itda.catalog-optional-media-projection.v2",
        "policy": policy,
        "candidate_set": candidate_set,
        "historical_lineage": {
            "terminal_history_sha256": HISTORICAL_TERMINAL_HISTORY_SHA256,
            "terminal_artifact_file_sha256": source_files[TERMINAL_FAILURE_REL.as_posix()],
            "terminal_root_sha256": HISTORICAL_TERMINAL_ROOT,
            "cited_roots": rebuilt_parents,
        },
        "source_files": source_files,
        "capabilities": {
            "provider_traffic_allowed": False,
            "credential_access_allowed": False,
            "vlm_inference_allowed": False,
            "catalog_membership_authority": False,
            "split_membership_authority": False,
            "schema_mutation_authority": False,
            "rights_waiver_authority": False,
        },
        "provider_attempts": (),
    }
    digest_fields = {
        **fields,
        "policy": policy.model_dump(mode="json"),
        "candidate_set": candidate_set.model_dump(mode="json"),
    }
    return OptionalMediaProjection(
        **fields,
        projection_sha256=canonical_sha256(digest_fields),
    )


def _publication_bytes(
    generation: OptionalMediaProjection,
) -> dict[str, bytes]:
    return {
        "policy.json": canonical_json_bytes(generation.policy.model_dump(mode="json")),
        "projected-candidates.json": canonical_json_bytes(
            generation.candidate_set.model_dump(mode="json")
        ),
        "projection-manifest.json": canonical_json_bytes(generation.model_dump(mode="json")),
    }


def _verify_existing_publication(
    target: Path,
    files: Mapping[str, bytes],
) -> None:
    if target.is_symlink() or not target.is_dir():
        raise OptionalMediaReplayError("content-addressed policy root cannot be a symlink")
    if {path.name for path in target.iterdir()} != set(files):
        raise OptionalMediaReplayError("existing policy publication inventory differs")
    for filename, expected in files.items():
        if (
            _read_regular_bytes_nofollow(
                target / filename,
                max_bytes=MAX_JSON_BYTES,
            )
            != expected
        ):
            raise OptionalMediaReplayError("existing policy publication differs from replay")


def publish_optional_media_projection(
    generation: OptionalMediaProjection,
    *,
    repository_root: Path | str,
    output_base: Path | str | None = None,
) -> Path:
    """Publish or verify one immutable content-addressed projection root."""

    root = Path(repository_root).resolve(strict=True)
    rebuilt = build_optional_media_projection(root)
    if generation != rebuilt:
        raise OptionalMediaReplayError("caller-supplied optional-media projection was patched")
    base = (
        root / OUTPUT_BASE_REL if output_base is None else Path(output_base).expanduser().absolute()
    )
    _assert_nofollow_ancestors(base)
    if base.is_symlink():
        raise OptionalMediaReplayError("optional-media output base cannot be a symlink")
    base.mkdir(parents=True, exist_ok=True)
    target = base / generation.projection_sha256
    files = _publication_bytes(generation)
    if target.exists() or target.is_symlink():
        _verify_existing_publication(target, files)
        return target

    with tempfile.TemporaryDirectory(prefix=".optional-media-", dir=base) as raw_stage:
        stage = Path(raw_stage)
        for filename, payload in files.items():
            descriptor = os.open(
                stage / filename,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o644,
            )
            try:
                written = os.write(descriptor, payload)
                if written != len(payload):
                    raise OSError("short write while staging optional-media projection")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        created_target = False
        created_files: list[Path] = []
        try:
            target.mkdir(mode=0o755)
            created_target = True
            for filename in files:
                destination = target / filename
                os.link(stage / filename, destination)
                created_files.append(destination)
            descriptor = os.open(target, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            descriptor = os.open(base, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except BaseException:
            for path in created_files:
                path.unlink(missing_ok=True)
            if created_target:
                target.rmdir()
            raise
    _verify_existing_publication(target, files)
    return target


def _only_projection_root(base: Path) -> Path:
    if base.is_symlink() or not base.is_dir():
        raise OptionalMediaReplayError("optional-media policy base is invalid")
    entries = list(base.iterdir())
    roots = [
        path
        for path in entries
        if path.is_dir()
        and not path.is_symlink()
        and len(path.name) == 64
        and all(character in "0123456789abcdef" for character in path.name)
    ]
    if len(entries) != 1 or len(roots) != 1:
        raise OptionalMediaReplayError("expected exactly one content-addressed policy root")
    return roots[0]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--build", action="store_true")
    modes.add_argument("--check", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repository_root = Path(__file__).resolve().parents[4]
    generation = build_optional_media_projection(repository_root)
    if args.build:
        published = publish_optional_media_projection(
            generation,
            repository_root=repository_root,
        )
    else:
        published = _only_projection_root(repository_root / OUTPUT_BASE_REL)
        if published.name != generation.projection_sha256:
            raise OptionalMediaReplayError("recorded policy root differs from replay")
        _verify_existing_publication(published, _publication_bytes(generation))
    print(generation.projection_sha256)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "AGGREGATE_REL",
    "ELIGIBILITY_ROOT",
    "ENTITY_PROJECTION_REL",
    "HISTORICAL_TERMINAL_HISTORY_SHA256",
    "HISTORICAL_TERMINAL_ROOT",
    "MAX_JSON_BYTES",
    "MAX_UNIVERSE_ROWS",
    "NORMALIZATION_REL",
    "NORMALIZATION_ROOT",
    "OUTPUT_BASE_REL",
    "OptionalMediaReplayError",
    "PREFLIGHT_REL",
    "PREFLIGHT_ROOT",
    "REQUEST_MANIFEST_REL",
    "TERMINAL_FAILURE_REL",
    "TERMINAL_HISTORY_REL",
    "build_optional_media_projection",
    "load_canonical_json_nofollow",
    "main",
    "project_sealed_universe",
    "publish_optional_media_projection",
]
