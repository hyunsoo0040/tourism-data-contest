"""Provider-free inspection and validation for the MVP PUBLIC catalog."""

from __future__ import annotations

import argparse
import os
import stat
import tempfile
from datetime import date
from pathlib import Path

from itda.contracts.mvp_public_catalog import (
    CatalogGapReport,
    OfficialDatasetPermissionMetadata,
    PublicEvidenceInventory,
    PublicPlaceCatalog,
    PublicPlaceRelations,
)
from itda.domain.canonical import canonical_json_bytes
from itda.pipeline.mvp_public_catalog import (
    build_catalog_gap_report,
    materialize_public_catalog,
    verify_permission_snapshot,
)


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[4]


def _default_source() -> Path:
    return (
        _repository_root()
        / "artifacts/catalog/optional-media-v2/policy"
        / "573e21213f7c0d157e33c7a510b9bcdb612dd517dfc70ba506ef7281ca0e9243"
        / "projected-candidates.json"
    )


def _default_output() -> Path:
    return _repository_root() / "artifacts/public/catalog/mvp-public-100-gap.json"


def _write_atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect tracked PUBLIC catalog feasibility")
    subparsers = parser.add_subparsers(dest="command", required=True)
    inspect = subparsers.add_parser("inspect-tracked")
    inspect.add_argument("--source", type=Path, default=_default_source())
    inspect.add_argument("--output", type=Path, default=_default_output())
    inspect.add_argument(
        "--permission",
        action="append",
        default=[],
        metavar="METADATA_JSON=RAW_SNAPSHOT",
    )
    verify = subparsers.add_parser("verify-gap")
    verify.add_argument("path", type=Path)
    permission = subparsers.add_parser("verify-permission")
    permission.add_argument("path", type=Path)
    permission.add_argument("--raw-snapshot", type=Path, required=True)
    materialize = subparsers.add_parser("materialize")
    materialize.add_argument("--v5-result", type=Path, required=True)
    materialize.add_argument("--v6-result", type=Path, required=True)
    materialize.add_argument("--reference-date", type=date.fromisoformat, required=True)
    materialize.add_argument("--permission", action="append", required=True)
    materialize.add_argument("--catalog-output", type=Path, required=True)
    materialize.add_argument("--evidence-output", type=Path, required=True)
    materialize.add_argument("--relations-output", type=Path, required=True)
    verify_catalog = subparsers.add_parser("verify-catalog")
    verify_catalog.add_argument("--catalog", type=Path, required=True)
    verify_catalog.add_argument("--evidence", type=Path, required=True)
    verify_catalog.add_argument("--relations", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "inspect-tracked":
        permissions, permission_snapshots = permission_inputs_from_cli(args.permission)
        report = build_catalog_gap_report(
            args.source,
            permissions=permissions,
            permission_snapshots=permission_snapshots,
        )
        _write_atomic(args.output, canonical_json_bytes(report.model_dump(mode="json")) + b"\n")
        print(_report_line(report))
        return 2
    if args.command == "verify-permission":
        permission = OfficialDatasetPermissionMetadata.model_validate_json(args.path.read_bytes())
        raw = _read_regular_bounded(args.raw_snapshot, maximum_bytes=2 * 1024 * 1024)
        verified_raw_sha256 = verify_permission_snapshot(permission, raw)
        print(
            f"dataset={permission.official_dataset_id} "
            f"metadata_sha256={permission.metadata_sha256} "
            f"verified_raw_sha256={verified_raw_sha256} "
            f"mvp_usage={'allowed' if permission.permits_mvp_use else 'blocked'} "
            "provider_traffic=false"
        )
        return 0 if permission.permits_mvp_use else 2
    if args.command == "materialize":
        permissions, snapshots = permission_inputs_from_cli(args.permission)
        tourapi = next(
            (row for row in permissions if row.official_dataset_id == "15101578"),
            None,
        )
        if tourapi is None:
            raise ValueError("TourAPI permission metadata is required")
        catalog, evidence, relations = materialize_public_catalog(
            args.v5_result,
            args.v6_result,
            permission=tourapi,
            permission_snapshots=snapshots,
            reference_date=args.reference_date,
        )
        outputs = (args.catalog_output, args.evidence_output, args.relations_output)
        if len(set(outputs)) != 3 or any(path.exists() for path in outputs):
            raise FileExistsError("materialization outputs must be three new paths")
        for path, value in zip(outputs, (catalog, evidence, relations), strict=True):
            _write_atomic(path, canonical_json_bytes(value.model_dump(mode="json")) + b"\n")
        print(
            f"catalog_sha256={catalog.catalog_sha256} places={len(catalog.places)} "
            f"evidence_inventory_sha256={evidence.inventory_sha256} "
            f"relations_sha256={relations.relations_sha256} provider_traffic=false"
        )
        return 0
    if args.command == "verify-catalog":
        catalog = PublicPlaceCatalog.model_validate_json(args.catalog.read_bytes())
        evidence = PublicEvidenceInventory.model_validate_json(args.evidence.read_bytes())
        relations = PublicPlaceRelations.model_validate_json(args.relations.read_bytes())
        if catalog.evidence_inventory_sha256 != evidence.inventory_sha256:
            raise ValueError("catalog evidence inventory binding does not match")
        if relations.catalog_sha256 != catalog.catalog_sha256:
            raise ValueError("catalog relations binding does not match")
        print(
            f"catalog_sha256={catalog.catalog_sha256} places={len(catalog.places)} "
            f"evidence={len(evidence.evidence)} relations={len(relations.relations)} "
            "provider_traffic=false"
        )
        return 0
    report = CatalogGapReport.model_validate_json(args.path.read_bytes())
    print(_report_line(report))
    return 2


def permission_inputs_from_cli(
    values: list[str],
) -> tuple[tuple[OfficialDatasetPermissionMetadata, ...], dict[str, bytes]]:
    if not values:
        return (), {}
    permissions: list[OfficialDatasetPermissionMetadata] = []
    snapshots: dict[str, bytes] = {}
    seen_datasets: set[str] = set()
    for value in values:
        metadata_path, separator, raw_path = value.partition("=")
        if separator != "=" or not metadata_path or not raw_path:
            raise ValueError("permission binding is invalid")
        permission = OfficialDatasetPermissionMetadata.model_validate_json(
            _read_regular_bounded(Path(metadata_path), maximum_bytes=64 * 1024)
        )
        if permission.official_dataset_id in seen_datasets:
            raise ValueError("permission dataset binding is duplicated")
        seen_datasets.add(permission.official_dataset_id)
        permissions.append(permission)
        snapshots[permission.metadata_sha256] = _read_regular_bounded(
            Path(raw_path), maximum_bytes=2 * 1024 * 1024
        )
    return tuple(permissions), snapshots


def _read_regular_bounded(path: Path, *, maximum_bytes: int) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= maximum_bytes:
        raise ValueError("official permission snapshot file is invalid")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size != metadata.st_size:
            raise ValueError("official permission snapshot file changed")
        raw = os.read(descriptor, maximum_bytes + 1)
    finally:
        os.close(descriptor)
    if len(raw) != metadata.st_size:
        raise ValueError("official permission snapshot file changed")
    return raw


def _report_line(report: CatalogGapReport) -> str:
    return (
        f"tracked={report.tracked_candidate_count} "
        f"description_ready_historical={report.description_ready_historical_count} "
        f"description_enrichment_candidates={report.description_enrichment_candidate_count} "
        f"description_gap={report.preliminary_description_gap_count} "
        f"strict_rights_state={report.strict_rights_state.lower()} "
        f"permission_metadata_present={str(report.permission_metadata_present).lower()} "
        "catalog_ready=false provider_traffic=false"
    )


if __name__ == "__main__":
    raise SystemExit(main())
