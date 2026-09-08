"""Collect and verify exact-once pytest ownership for the Phase 3 gate."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest


class _NodeManifestPlugin:
    def __init__(self, output: Path) -> None:
        self._output = output

    def pytest_collection_finish(self, session: pytest.Session) -> None:
        node_ids = [normalize_node_id(item.nodeid) for item in session.items]
        self._output.write_text(
            json.dumps(node_ids, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )


def normalize_node_id(node_id: str) -> str:
    return node_id.removeprefix("backend/")


def collect_node_manifest(output: Path, pytest_args: Sequence[str]) -> int:
    output.parent.mkdir(parents=True, exist_ok=True)
    return int(
        pytest.main(
            [*pytest_args, "--collect-only", "-q"],
            plugins=[_NodeManifestPlugin(output)],
        )
    )


def verify_node_ownership(
    manifests: Mapping[str, Sequence[str]], expected_file_owners: Mapping[str, str]
) -> None:
    owners_by_node: dict[str, list[str]] = defaultdict(list)
    for owner, node_ids in manifests.items():
        for node_id in node_ids:
            owners_by_node[normalize_node_id(node_id)].append(owner)

    duplicates = {node_id: owners for node_id, owners in owners_by_node.items() if len(owners) != 1}
    if duplicates:
        details = ", ".join(
            f"{node_id} ({'/'.join(owners)})" for node_id, owners in sorted(duplicates.items())
        )
        raise ValueError(f"duplicate pytest node ownership: {details}")

    for file_path, expected_owner in expected_file_owners.items():
        prefix = f"{normalize_node_id(file_path)}::"
        matching = {
            owner
            for node_id, owners in owners_by_node.items()
            if node_id.startswith(prefix)
            for owner in owners
        }
        if not matching:
            raise ValueError(f"no pytest nodes collected for {file_path}")
        if matching != {expected_owner}:
            actual = ", ".join(sorted(matching))
            raise ValueError(
                f"pytest owner mismatch for {file_path}: {actual}; expected {expected_owner}"
            )


def _load_manifest(path: Path) -> list[str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list) or not all(isinstance(item, str) for item in payload):
        raise ValueError(f"invalid pytest node manifest: {path}")
    return payload


def _parse_assignment(value: str) -> tuple[str, str]:
    name, separator, assigned = value.partition("=")
    if not separator or not name or not assigned:
        raise argparse.ArgumentTypeError("expected NAME=VALUE")
    return name, assigned


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    collect_parser = subparsers.add_parser("collect")
    collect_parser.add_argument("--output", type=Path, required=True)
    collect_parser.add_argument("pytest_args", nargs=argparse.REMAINDER)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--manifest", action="append", type=_parse_assignment, required=True)
    verify_parser.add_argument("--expect", action="append", type=_parse_assignment, required=True)

    arguments = parser.parse_args()
    if arguments.command == "collect":
        pytest_args = arguments.pytest_args
        if pytest_args[:1] == ["--"]:
            pytest_args = pytest_args[1:]
        raise SystemExit(collect_node_manifest(arguments.output, pytest_args))

    manifests = {owner: _load_manifest(Path(path)) for owner, path in arguments.manifest}
    verify_node_ownership(manifests, dict(arguments.expect))
    print("phase-03-check ownership verified at pytest-node collection level")


if __name__ == "__main__":
    main()
