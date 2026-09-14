"""Run the supplementary development-only formula comparison without API calls."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from itda.authenticity.ranking_comparison import evaluate


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument(
        "--development", type=Path, default=Path("artifacts/authenticity-v1/20260911/development")
    )
    args = parser.parse_args()
    result = evaluate(args.development, args.repository)
    print(json.dumps({k: result[k] for k in ("scope", "places", "groups", "report_sha256")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
