"""Export the canonical questionnaire projection as stable JSON."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from itda.contracts.questionnaire import questionnaire_artifact_bytes
from itda.contracts.questionnaire_v2 import QUESTIONNAIRE_DEFINITION_V2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Destination for the questionnaire artifact JSON",
    )
    parser.add_argument(
        "--version",
        choices=("v1", "v2"),
        default="v2",
        help="Which questionnaire generation to export (default: v2)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Write the generated questionnaire artifact and return a process status."""

    args = _parser().parse_args(argv)
    output: Path = args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    if args.version == "v2":
        import json

        rendered = json.dumps(
            QUESTIONNAIRE_DEFINITION_V2.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        output.write_text(f"{rendered}\n", encoding="utf-8")
    else:
        output.write_bytes(questionnaire_artifact_bytes())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
