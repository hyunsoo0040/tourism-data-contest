"""Summarize the retained model usage records without making network calls."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from itda.authenticity.usage import summarize


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("artifacts/authenticity-v1/20260911"))
    args = parser.parse_args()
    r = summarize(args.root, args.root / "model-usage.json")
    print(
        json.dumps(
            {
                k: r[k]
                for k in (
                    "unique_recorded_exchanges",
                    "deduplicated_cache_copies",
                    "reported_total_tokens",
                )
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
