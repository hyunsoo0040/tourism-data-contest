"""Export hash-linked catalog audit projections from canonical JSON truth."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from itda.pipeline.export_catalog_audit import export_catalog_audit, load_catalog_audit


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--audit-json",
        type=Path,
        required=True,
        help="Canonical catalog-audit.json input; projections are rejected as truth",
    )
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--format", choices=("all",), default="all")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    audit = load_catalog_audit(args.audit_json)
    exported = export_catalog_audit(audit, args.output_root)
    print(
        json.dumps(
            {
                "audit_sha256": audit.audit_sha256,
                "data_version": audit.data_version,
                "format": args.format,
                "output_hashes": exported.projection_manifest.output_hashes,
                "projection_manifest_sha256": (
                    exported.projection_manifest.projection_manifest_sha256
                ),
                "schema_version": audit.schema_version,
                "source_version": audit.source_version,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
