"""Export the FastAPI OpenAPI document as a deterministic committed artifact."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from itda.api.main import app


def openapi_document_bytes() -> bytes:
    rendered = json.dumps(
        app.openapi(),
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    return f"{rendered}\n".encode()


def export_openapi(output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(openapi_document_bytes())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    export_openapi(arguments.output)


if __name__ == "__main__":
    main()
