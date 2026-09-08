"""Fail-closed entry point for human-authorized staged discovery collection."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from itda.contracts.catalog_discovery import verify_request_generation

_REQUESTS_RELATIVE = Path("artifacts/restricted/catalog/v2/supplemental/discovery/requests")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify D1 collection inputs or a completed collection generation."
    )
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--source", choices=("d1",), required=True)
    parser.add_argument("--request-generation-sha256")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--discover-exact-success-under", type=Path)
    return parser


def _select_request_root(repo_root: Path, digest: str | None) -> Path:
    requests_root = repo_root / _REQUESTS_RELATIVE
    if digest is not None:
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ValueError("request-generation SHA-256 is malformed")
        return requests_root / digest
    candidates = sorted(path for path in requests_root.iterdir() if path.is_dir())
    if len(candidates) != 1:
        raise ValueError("exactly one D1 request generation must be selected")
    return candidates[0]


def _discover_collection_success(root: Path) -> Path:
    candidates = sorted(
        path
        for path in root.iterdir()
        if path.is_dir() and (path / "collection-generation-manifest.json").is_file()
    )
    if len(candidates) != 1:
        raise ValueError("exactly one D1 collection generation must verify")
    return candidates[0]


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repo_root = args.repo_root.resolve(strict=True)
    if not args.check:
        raise ValueError(
            "collection is blocked until the exact blocking-human checkpoint "
            "supplies dataset-specific approval, protected credential-file path, "
            "and fresh itda-auth-v2 authority"
        )
    request_root = _select_request_root(
        repo_root,
        args.request_generation_sha256,
    )
    manifest = verify_request_generation(request_root)
    result: dict[str, object] = {
        "source": "d1",
        "request_generation_sha256": manifest["request_generation_sha256"],
        "request_generation_valid": True,
        "provider_requests_sent": 0,
        "credential_file_opened": False,
        "authority_consumed": False,
    }
    if args.discover_exact_success_under is not None:
        collection_root = _discover_collection_success(
            args.discover_exact_success_under.resolve(strict=True)
        )
        result["collection_generation"] = collection_root.name
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
