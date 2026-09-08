#!/usr/bin/env python3
"""Read-only fetcher for the authorized upstream UI files (07-02).

Fetches each file listed in fixtures/upstream-ui/provenance.json from the
frozen upstream commit through the GitHub contents API, writes the exact
bytes into fixtures/upstream-ui/original/ (mirroring upstream layout), and
verifies SHA-256 + byte count against the manifest. Fails closed on any
mismatch: the mismatching file is not kept.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import sys
import urllib.parse
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = REPO_ROOT / "fixtures" / "upstream-ui" / "provenance.json"
OUT_DIR = REPO_ROOT / "fixtures" / "upstream-ui" / "original"
COMMIT = "d3f2ac2aa7ed866a753b4916b6f9544b22ae0611"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the vendored bytes without network access or filesystem writes",
    )
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["upstream"]["commit"] == COMMIT
    if not args.check:
        OUT_DIR.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    for entry in manifest["files"]:
        upstream_path: str = entry["upstream_path"]
        expected_sha: str = entry["sha256"]
        expected_bytes: int = entry["bytes"]
        out_path = OUT_DIR / upstream_path
        if args.check:
            try:
                data = out_path.read_bytes()
            except OSError:
                failures.append(f"{upstream_path}: vendored file missing")
                continue
        else:
            api_path = urllib.parse.quote(upstream_path, safe="/")
            url = f"repos/hyunsoo0040/tourism-data-contest/contents/{api_path}?ref={COMMIT}"
            raw = subprocess.run(
                ["gh", "api", url, "--jq", ".content"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            data = base64.b64decode(raw)
        actual_sha = hashlib.sha256(data).hexdigest()
        if actual_sha != expected_sha or len(data) != expected_bytes:
            failures.append(
                f"{upstream_path}: sha {actual_sha} len {len(data)} "
                f"(expected {expected_sha} {expected_bytes})"
            )
            continue
        if not args.check:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(data)
        print(f"OK {upstream_path} {len(data)}B {actual_sha[:12]}")
    if failures:
        for line in failures:
            print(f"MISMATCH {line}", file=sys.stderr)
        return 1
    mode = "vendored" if args.check else "fetched"
    print(f"all {len(manifest['files'])} files verified byte-for-byte ({mode})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
