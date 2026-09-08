"""Retired Phase 4 dependency gate.

The only v1 approval was consumed.  This tombstone deliberately performs no
file parsing, executable probing, dependency synchronization, or receipt
publication.  A future dependency gate must use a new schema and module.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence

LEGACY_GATE_EXHAUSTED_MESSAGE = (
    "legacy Phase 4 dependency approval is exhausted; a new approval must bind "
    "trusted mise, uv, Node, and gsd-tools executable digests"
)


def main(argv: Sequence[str] | None = None) -> int:
    """Reject every invocation without inspecting caller-controlled inputs."""

    del argv
    print(f"dependency gate rejected: {LEGACY_GATE_EXHAUSTED_MESSAGE}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
