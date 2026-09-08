"""Prepare the one human-approved BGE-M3 revision after D-11 verification."""

from __future__ import annotations

import argparse
import importlib
import json
import shutil
from pathlib import Path

from itda.analysis.text.model_artifacts import (
    APPROVED_MODEL_ID,
    APPROVED_MODEL_REVISION,
    VerifiedFreezeGuard,
    build_model_manifest,
    verify_approved_packages,
    write_canonical_no_replace,
)
from itda.domain.canonical import canonical_json_bytes


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download-approved", action="store_true")
    parser.add_argument("--revision", required=True)
    parser.add_argument("--freeze-receipt", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.download_approved:
        raise SystemExit("approved model preparation requires --download-approved")
    if args.revision != APPROVED_MODEL_REVISION:
        raise SystemExit("approved model revision mismatch")

    # This read and full receipt verification deliberately precede output/cache resolution.
    _, freeze_digest = VerifiedFreezeGuard.from_path(args.freeze_receipt)
    package_set_sha256 = verify_approved_packages()

    snapshot_name = f"bge-m3-{APPROVED_MODEL_REVISION}"
    snapshot_root = args.output.parent / snapshot_name
    if args.output.exists() or args.output.is_symlink():
        raise SystemExit("model manifest output already exists")
    if snapshot_root.is_symlink() or (snapshot_root.exists() and not snapshot_root.is_dir()):
        raise SystemExit("approved model snapshot destination is unsafe")
    args.output.parent.mkdir(parents=True, exist_ok=True)

    snapshot_download = importlib.import_module("huggingface_hub").snapshot_download

    resolved = Path(
        snapshot_download(
            repo_id=APPROVED_MODEL_ID,
            revision=APPROVED_MODEL_REVISION,
            local_dir=snapshot_root,
            token=False,
        )
    )
    if resolved.resolve() != snapshot_root.resolve():
        raise SystemExit("approved model snapshot resolved outside the pinned destination")
    transfer_metadata = snapshot_root / ".cache"
    if transfer_metadata.exists():
        if transfer_metadata.is_symlink() or not transfer_metadata.is_dir():
            raise SystemExit("model transfer metadata path is unsafe")
        shutil.rmtree(transfer_metadata)
    manifest = build_model_manifest(
        snapshot_root=snapshot_root,
        snapshot_directory=snapshot_name,
        freeze_receipt_sha256=freeze_digest,
        package_set_sha256=package_set_sha256,
    )
    write_canonical_no_replace(
        args.output,
        canonical_json_bytes(manifest.model_dump(mode="json")),
    )
    print(
        json.dumps(
            {
                "manifest_sha256": manifest.manifest_sha256,
                "model_revision": manifest.model_revision,
                "status": "APPROVED_SNAPSHOT_PREPARED",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
