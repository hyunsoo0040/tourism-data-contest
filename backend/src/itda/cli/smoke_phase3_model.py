"""Verify and exercise the prepared Phase 3 encoder with network access denied."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from itda.analysis.text.model_artifacts import smoke_local_model


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-manifest", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = smoke_local_model(args.model_manifest)
    except (OSError, RuntimeError, ValueError) as exc:
        raise SystemExit(f"offline model smoke failed: {exc}") from exc
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
