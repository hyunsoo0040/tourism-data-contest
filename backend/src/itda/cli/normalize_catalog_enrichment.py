"""Build, publish, or verify one explicit catalog-enrichment evidence sidecar."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from itda.cli.collect_catalog_enrichment import (
    SelectedRound,
    _canonical_lines,
    _load_selected_round,
    _regular_file_bytes,
    verify_and_seal_kto_recovery_collection,
)
from itda.cli.plan_catalog_kto_recovery import (
    _assert_private_directory,
    _publish_private_files,
    discover_exact_kto_eligibility_success,
)
from itda.contracts.catalog_audit import CatalogAudit
from itda.contracts.catalog_enrichment_evidence import (
    EnrichmentEvidenceSidecar,
    build_enrichment_sidecar,
    canonical_sidecar_bytes,
    normalize_kto_recovery_response,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

SIDECAR_NAME = "evidence-sidecars.json"
KTO_COLLECTIONS_REL = Path("artifacts/restricted/catalog/v2/supplemental/kto-recovery/collections")
KTO_ELIGIBILITY_REL = Path("artifacts/restricted/catalog/v2/supplemental/kto-recovery/eligibility")
KTO_DECISIONS_REL = Path("artifacts/restricted/catalog/v2/supplemental/kto-recovery/decisions")
KTO_NORMALIZATIONS_REL = Path(
    "artifacts/restricted/catalog/v2/supplemental/kto-recovery/normalizations"
)
KTO_CATALOG_AUDIT_REL = Path("artifacts/restricted/catalog/v1/review/catalog-audit.json")
KTO_NORMALIZATION_FILE = "normalization.json"


@dataclass(frozen=True)
class KtoRecoveryNormalization:
    collection_base: str
    collection_success_root: str
    request_manifest_sha256: str
    normalization_root_sha256: str
    request_count: int
    response_count: int
    success_empty_count: int
    rights_attestation_sha256: str
    responses: tuple[dict[str, Any], ...]
    payload: dict[str, Any]

    @property
    def files(self) -> dict[str, bytes]:
        return {
            KTO_NORMALIZATION_FILE: canonical_json_bytes(
                {
                    "payload": self.payload,
                    "normalization_root_sha256": self.normalization_root_sha256,
                }
            )
        }


def _only_direct_digest_root(base: Path, *, label: str) -> Path:
    roots = [
        path.resolve(strict=True)
        for path in base.iterdir()
        if path.is_dir() and len(path.name) == 64
    ]
    if len(roots) != 1:
        raise ValueError(f"expected exactly one direct {label} root")
    return roots[0]


def build_kto_recovery_normalization(
    repository_root: Path | str,
) -> KtoRecoveryNormalization:
    """Replay and normalize only the exact sealed Plan 48 collection."""

    root = Path(repository_root).resolve(strict=True)
    collections_base = (root / KTO_COLLECTIONS_REL).resolve(strict=True)
    collection_result = verify_and_seal_kto_recovery_collection(
        root,
        collections_base=collections_base,
    )
    collection_root = _only_direct_digest_root(
        collections_base,
        label="Plan 48 collection",
    )
    if collection_root.name != collection_result["kto_collection_base"]:
        raise ValueError("verified KTO collection base differs from exact discovery")
    eligibility_base = (root / KTO_ELIGIBILITY_REL).resolve(strict=True)
    decision_root = _only_direct_digest_root(
        (root / KTO_DECISIONS_REL).resolve(strict=True),
        label="KTO policy decision",
    )
    eligibility_root = discover_exact_kto_eligibility_success(
        root,
        eligibility_base,
        decision_receipt_root=decision_root,
    )
    request_manifest_bytes = _regular_file_bytes(eligibility_root / "request-manifest.json")
    request_manifest = json.loads(request_manifest_bytes)
    requests_value = request_manifest.get("requests")
    if (
        not isinstance(requests_value, list)
        or len(requests_value) != 48
        or request_manifest.get("request_count") != 48
    ):
        raise ValueError("exact KTO request manifest no longer contains 48 requests")
    request_manifest_sha256 = hashlib.sha256(request_manifest_bytes).hexdigest()
    if request_manifest_sha256 != collection_result["kto_request_manifest_sha256"]:
        raise ValueError("KTO collection is detached from the request manifest")
    requests = {
        str(row["request_identity"]): row for row in requests_value if isinstance(row, dict)
    }
    if len(requests) != 48:
        raise ValueError("KTO request manifest identities are not unique")
    terminal_rows = _canonical_lines(collection_root / "terminal-ledger.jsonl")
    terminals = {
        str(row["request_identity"]): row for row in terminal_rows if isinstance(row, dict)
    }
    if set(terminals) != set(requests) or len(terminals) != 48:
        raise ValueError("KTO terminal ledger differs from the exact request inventory")
    audit = CatalogAudit.model_validate_json(_regular_file_bytes(root / KTO_CATALOG_AUDIT_REL))
    grant = next(
        (row for row in audit.grants if row.official_dataset_id == "15101578"),
        None,
    )
    if grant is None:
        raise ValueError("catalog audit lacks exact TourAPI dataset rights")

    normalized: list[dict[str, Any]] = []
    for request in requests_value:
        if not isinstance(request, dict):
            raise ValueError("KTO request manifest contains a non-object")
        identity = str(request["request_identity"])
        terminal = terminals[identity]
        raw_relative_path = terminal.get("raw_relative_path")
        if not isinstance(raw_relative_path, str):
            raise ValueError("KTO terminal row lacks a raw evidence path")
        raw_path = (collection_root / raw_relative_path).resolve(strict=True)
        if collection_root not in raw_path.parents:
            raise ValueError("KTO raw evidence path escapes the collection root")
        normalized.append(
            normalize_kto_recovery_response(
                planned_request=request,
                terminal_record=terminal,
                raw_body=_regular_file_bytes(raw_path),
                grant=grant,
            )
        )
    empty_count = sum(row["transport_state"] == "SUCCESS_EMPTY" for row in normalized)
    if empty_count != collection_result["success_empty_count"]:
        raise ValueError("normalized success-empty count differs from the collection seal")
    rights_root = canonical_sha256(
        [
            {
                "request_identity": row["request_identity"],
                "dataset_rights": row["dataset_rights"],
                "asset_rights": row["asset_rights"],
            }
            for row in normalized
        ]
    )
    payload: dict[str, Any] = {
        "schema_version": "itda.kto-recovery-normalization.v1",
        "status": "SUCCESS",
        "kto_collection_base": collection_root.name,
        "kto_collection_success_root": collection_result["kto_collection_success_root"],
        "kto_collection_manifest_sha256": collection_result["kto_collection_manifest_sha256"],
        "kto_eligibility_root": eligibility_root.name,
        "kto_request_manifest_sha256": request_manifest_sha256,
        "typed_intro_policy_sha256": collection_result["typed_intro_policy_sha256"],
        "request_count": len(requests),
        "response_count": len(normalized),
        "success_empty_count": empty_count,
        "kto_rights_attestation_sha256": rights_root,
        "responses": normalized,
        "responses_root_sha256": canonical_sha256(normalized),
    }
    normalization_root = canonical_sha256(payload)
    return KtoRecoveryNormalization(
        collection_base=collection_root.name,
        collection_success_root=str(collection_result["kto_collection_success_root"]),
        request_manifest_sha256=request_manifest_sha256,
        normalization_root_sha256=normalization_root,
        request_count=len(requests),
        response_count=len(normalized),
        success_empty_count=empty_count,
        rights_attestation_sha256=rights_root,
        responses=tuple(normalized),
        payload=payload,
    )


def publish_kto_recovery_normalization(
    generation: KtoRecoveryNormalization,
    *,
    repository_root: Path | str,
    output_base: Path | str | None = None,
) -> Path:
    """Publish one double-replayed private KTO normalization generation."""

    root = Path(repository_root).resolve(strict=True)
    rebuilt = build_kto_recovery_normalization(root)
    if generation != rebuilt:
        raise ValueError("caller-supplied KTO normalization was patched")
    base = (
        root / KTO_NORMALIZATIONS_REL
        if output_base is None
        else Path(output_base).expanduser().resolve()
    )
    destination = base / generation.normalization_root_sha256
    if destination.exists():
        _assert_private_directory(
            destination,
            expected_files={KTO_NORMALIZATION_FILE},
        )
        if (
            _regular_file_bytes(destination / KTO_NORMALIZATION_FILE)
            != generation.files[KTO_NORMALIZATION_FILE]
        ):
            raise ValueError("existing KTO normalization root differs from replay")
        return destination
    _publish_private_files(
        destination=destination,
        files=generation.files,
        temporary_prefix=".kto-normalization-",
    )
    _assert_private_directory(
        destination,
        expected_files={KTO_NORMALIZATION_FILE},
    )
    if (
        _regular_file_bytes(destination / KTO_NORMALIZATION_FILE)
        != generation.files[KTO_NORMALIZATION_FILE]
    ):
        raise ValueError("published KTO normalization differs from replay")
    return destination


def load_round_context(
    round_root: Path | str,
    round_id: str,
) -> SelectedRound:
    """Expose the collector's exact round-pair and ancestry verification."""

    return _load_selected_round(round_root, round_id)


def _repository_root(start: Path) -> Path:
    current = start.resolve(strict=True)
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    raise ValueError("selected round is not inside a repository")


def _catalog_audit_path(
    selected: SelectedRound,
    supplied: Path | None,
) -> Path:
    if supplied is None:
        result = (
            _repository_root(selected.root)
            / "artifacts/restricted/catalog/v1/review/catalog-audit.json"
        )
    else:
        result = supplied.expanduser()
        if not result.is_absolute():
            result = _repository_root(selected.root) / result
    resolved = result.resolve(strict=True)
    expected = (
        _repository_root(selected.root)
        / "artifacts/restricted/catalog/v1/review/catalog-audit.json"
    ).resolve(strict=True)
    if resolved != expected:
        raise ValueError("catalog audit must be the exact protected v1 authority")
    return resolved


def _build_twice(
    *,
    selected: SelectedRound,
    catalog_audit_path: Path,
) -> tuple[EnrichmentEvidenceSidecar, bytes]:
    first = build_enrichment_sidecar(
        round_root=selected.root,
        round_id=selected.round_id,
        catalog_audit_path=catalog_audit_path,
    )
    second = build_enrichment_sidecar(
        round_root=selected.root,
        round_id=selected.round_id,
        catalog_audit_path=catalog_audit_path,
    )
    first_bytes = canonical_sidecar_bytes(first)
    second_bytes = canonical_sidecar_bytes(second)
    if first_bytes != second_bytes:
        raise ValueError("selected-round evidence sidecar is not byte-deterministic")
    return first, first_bytes


def publish_sidecar(
    *,
    selected: SelectedRound,
    sidecar: EnrichmentEvidenceSidecar,
    payload: bytes,
) -> Path:
    """Publish once at the exact selected-round path with private permissions."""

    if sidecar.round_id != selected.round_id or sidecar.round_root != _round_value(selected.root):
        raise ValueError("sidecar is detached from the exact selected round")
    if payload != canonical_sidecar_bytes(sidecar):
        raise ValueError("publication bytes do not match the validated sidecar")
    destination = Path(selected.root) / SIDECAR_NAME
    publish_bytes_no_replace(destination, payload)
    return destination


def _unlink_matching(path: Path, *, device: int, inode: int) -> None:
    try:
        current = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISREG(current.st_mode) and current.st_dev == device and current.st_ino == inode:
        path.unlink()


def publish_bytes_no_replace(destination: Path, payload: bytes) -> None:
    """Atomically link private complete bytes into a previously absent path."""

    destination = destination.parent.resolve(strict=True) / destination.name
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    opened = os.fstat(descriptor)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("sidecar publication made no write progress")
            view = view[written:]
        os.fsync(descriptor)
        completed = os.fstat(descriptor)
        if (
            not stat.S_ISREG(completed.st_mode)
            or completed.st_dev != opened.st_dev
            or completed.st_ino != opened.st_ino
            or completed.st_size != len(payload)
            or completed.st_mode & 0o777 != 0o600
            or completed.st_nlink != 1
        ):
            raise ValueError("temporary sidecar identity or private mode changed")
    except BaseException:
        os.close(descriptor)
        _unlink_matching(
            temporary,
            device=opened.st_dev,
            inode=opened.st_ino,
        )
        raise
    else:
        os.close(descriptor)
    try:
        os.link(temporary, destination, follow_symlinks=False)
        directory_descriptor = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        _unlink_matching(
            temporary,
            device=opened.st_dev,
            inode=opened.st_ino,
        )


def _round_value(root: Path) -> str:
    parts = root.parts
    try:
        index = parts.index("artifacts")
    except ValueError:
        return root.as_posix()
    return Path(*parts[index:]).as_posix()


def verify_sidecar(
    path: Path | str,
    *,
    selected: SelectedRound,
    catalog_audit_path: Path,
) -> dict[str, object]:
    """Rebuild the selected round and compare exact canonical publication bytes."""

    supplied = Path(path).expanduser()
    if not supplied.is_absolute():
        supplied = _repository_root(selected.root) / supplied
    resolved = supplied.resolve(strict=True)
    expected = (selected.root / SIDECAR_NAME).resolve(strict=True)
    if resolved != expected:
        raise ValueError("sidecar check path is outside the exact selected round")
    payload = _regular_file_bytes(resolved)
    try:
        published = EnrichmentEvidenceSidecar.model_validate_json(payload)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("published sidecar does not satisfy its strict contract") from exc
    if canonical_sidecar_bytes(published) != payload:
        raise ValueError("published sidecar is not canonical JSON")
    rebuilt, rebuilt_bytes = _build_twice(
        selected=selected,
        catalog_audit_path=catalog_audit_path,
    )
    if published != rebuilt or payload != rebuilt_bytes:
        raise ValueError("published sidecar differs from selected-round evidence")
    return {
        "round_id": selected.round_id,
        "sidecar_sha256": published.sidecar_sha256,
        "response_count": published.response_count,
        "terminal_status_counts": published.terminal_status_counts,
        "operation_status_counts": published.operation_status_counts,
        "field_state_counts": published.field_state_counts,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=("Normalize only one explicit immutable catalog-enrichment round.")
    )
    parser.add_argument("--round-root", type=Path, required=True)
    parser.add_argument("--round-id", required=True)
    parser.add_argument("--catalog-audit", type=Path)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--build", action="store_true")
    action.add_argument("--publish", action="store_true")
    action.add_argument("--check", type=Path)
    return parser


def kto_recovery_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Normalize or verify the exact sealed Plan 48 KTO collection."
    )
    parser.add_argument("--repo-root", type=Path, required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--normalize-kto-recovery", action="store_true")
    action.add_argument("--verify-kto-recovery", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = tuple(argv) if argv is not None else tuple(sys.argv[1:])
    is_kto_recovery = bool(
        {
            "--normalize-kto-recovery",
            "--verify-kto-recovery",
        }.intersection(arguments)
    )
    if is_kto_recovery:
        args = kto_recovery_parser().parse_args(arguments)
        repository_root = args.repo_root.resolve(strict=True)
        generation = build_kto_recovery_normalization(repository_root)
        published_path: str | None = None
        if args.normalize_kto_recovery:
            published_path = publish_kto_recovery_normalization(
                generation,
                repository_root=repository_root,
            ).as_posix()
        else:
            expected = (
                repository_root / KTO_NORMALIZATIONS_REL / generation.normalization_root_sha256
            )
            if not expected.is_dir():
                raise ValueError("exact KTO normalization root is absent")
            publish_kto_recovery_normalization(
                generation,
                repository_root=repository_root,
            )
            published_path = expected.as_posix()
        print(
            json.dumps(
                {
                    "status": "SUCCESS",
                    "kto_collection_base": generation.collection_base,
                    "kto_collection_success_root": (generation.collection_success_root),
                    "kto_normalization_root": (generation.normalization_root_sha256),
                    "kto_rights_attestation_sha256": (generation.rights_attestation_sha256),
                    "response_count": generation.response_count,
                    "success_empty_count": generation.success_empty_count,
                    "published_path": published_path,
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 0
    args = _parser().parse_args(arguments)
    selected = load_round_context(args.round_root, args.round_id)
    audit_path = _catalog_audit_path(selected, args.catalog_audit)
    if args.check is not None:
        result = verify_sidecar(
            args.check,
            selected=selected,
            catalog_audit_path=audit_path,
        )
    else:
        sidecar, payload = _build_twice(
            selected=selected,
            catalog_audit_path=audit_path,
        )
        destination: str | None = None
        if args.publish:
            destination = publish_sidecar(
                selected=selected,
                sidecar=sidecar,
                payload=payload,
            ).as_posix()
        result = {
            "round_id": selected.round_id,
            "sidecar_sha256": sidecar.sidecar_sha256,
            "response_count": sidecar.response_count,
            "terminal_status_counts": sidecar.terminal_status_counts,
            "operation_status_counts": sidecar.operation_status_counts,
            "field_state_counts": sidecar.field_state_counts,
            "published_path": destination,
        }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
