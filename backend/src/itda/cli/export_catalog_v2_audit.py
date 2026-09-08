"""Build or verify the membership-free final catalog-v2 audit bundle."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from itda.pipeline.export_catalog_v2_audit import (
    build_catalog_v2_audit,
    verify_catalog_v2_audit,
)


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    action = command.add_mutually_exclusive_group(required=True)
    action.add_argument("--build", type=Path, metavar="OUTPUT")
    action.add_argument("--verify", type=Path, metavar="OUTPUT")
    command.add_argument("--sqlite-seal-receipt", type=Path, required=True)
    return command


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[4]


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.build is not None:
            result = build_catalog_v2_audit(
                repository_root=_repository_root(),
                sqlite_seal_receipt=args.sqlite_seal_receipt,
                output_root=args.build,
            )
            disposition = "BUILT"
        else:
            result = verify_catalog_v2_audit(
                args.verify,
                repository_root=_repository_root(),
                sqlite_seal_receipt=args.sqlite_seal_receipt,
            )
            disposition = "VERIFIED"
    except (OSError, ValueError):
        print(json.dumps({"disposition": "REJECTED", "reason": "final audit validation failed"}))
        return 2
    print(
        json.dumps(
            {
                "disposition": disposition,
                "manifest_sha256": result.manifest_sha256,
                "row_count": result.row_count,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
