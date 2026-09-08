"""Validate and seal one synthetic split manifest through the restricted DB interface."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import psycopg

from itda.contracts.manifest import ManifestSeal, SplitManifest
from itda.domain.canonical import canonical_json_bytes, canonical_sha256


class ManifestAlreadySealedError(ValueError):
    """Raised before persistence when a caller tries to replace an existing seal."""


def create_manifest_seal(
    manifest: SplitManifest,
    *,
    sealed_at: datetime,
    existing_seal: ManifestSeal | None = None,
) -> ManifestSeal:
    """Build immutable metadata, refusing an application-level second seal."""

    if existing_seal is not None:
        raise ManifestAlreadySealedError(
            f"manifest {manifest.manifest_version!r} is already sealed"
        )
    return ManifestSeal(
        manifest_version=manifest.manifest_version,
        canonicalization_version=manifest.canonicalization_version,
        manifest_sha256=canonical_sha256(manifest.canonical_payload()),
        sealed_at=sealed_at,
        member_count=len(manifest.members),
        dev_count=sum(member.split == "DEV" for member in manifest.members),
        blind_count=sum(member.split == "BLIND" for member in manifest.members),
    )


def seal_manifest(
    connection: psycopg.Connection[tuple[object, ...]],
    manifest: SplitManifest,
    seal: ManifestSeal,
) -> None:
    """Call the sole database capability exposed to the dedicated sealer role."""

    canonical_json = canonical_json_bytes(manifest.canonical_payload()).decode("utf-8")
    connection.execute(
        "SELECT blind_eval.seal_manifest_v1(%s, %s, %s)",
        (
            canonical_json,
            seal.manifest_sha256,
            seal.sealed_at,
        ),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--dsn",
        required=True,
        help="Dedicated sealer DSN; owner/admin credentials are not accepted implicitly",
    )
    parser.add_argument(
        "--sealed-at",
        type=datetime.fromisoformat,
        default=None,
        help="Optional ISO-8601 UTC timestamp; defaults to the current UTC time",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Validate a local manifest and commit it through the restricted DB function."""

    args = _parser().parse_args(argv)
    manifest = SplitManifest.model_validate_json(args.manifest.read_text(encoding="utf-8"))
    sealed_at = args.sealed_at or datetime.now(UTC)
    seal = create_manifest_seal(manifest, sealed_at=sealed_at)

    with psycopg.connect(args.dsn) as connection:
        seal_manifest(connection, manifest, seal)

    print(json.dumps(seal.model_dump(mode="json"), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
