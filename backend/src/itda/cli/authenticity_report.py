"""Build the versioned evidence report using only local public artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from itda.authenticity.report import build


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--root", type=Path, default=Path("artifacts/authenticity-v1/20260911"))
    parser.add_argument(
        "--output", type=Path, default=Path("artifacts/authenticity-v1/20260911/report")
    )
    parser.add_argument("--final", action="store_true")
    args = parser.parse_args()
    print(json.dumps(build(args.repository, args.root, args.output, final=args.final)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
