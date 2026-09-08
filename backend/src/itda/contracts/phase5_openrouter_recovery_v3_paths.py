"""Fixed filesystem coordinates for the disjoint r3/v3 recovery lane.

Imported lazily by the contracts module so the snapshot constants stay
importable in any process; every path is resolved from THIS module's own
location, never from caller context.
"""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]

OPENROUTER_V3_SNAPSHOT_PATH = (
    REPOSITORY_ROOT / "backend/src/itda/providers/openrouter_ox_alpha_api_contract_v3.json"
)

OPENROUTER_V2_PUBLIC_PACKET_RELATIVE = "artifacts/public/phase5/openrouter-recovery-v2-request.json"
OPENROUTER_V2_PUBLIC_PACKET_PATH = REPOSITORY_ROOT / OPENROUTER_V2_PUBLIC_PACKET_RELATIVE

OPENROUTER_V3_PUBLIC_REQUEST_RELATIVE = (
    "artifacts/public/phase5/openrouter-recovery-v3-request.json"
)
OPENROUTER_V3_PROTECTED_ROOT_RELATIVE = (
    "artifacts/restricted/catalog/phase5-openrouter-recovery-r3"
)
OPENROUTER_V3_TERMINAL_RELATIVE = (
    "artifacts/reports/phase5/openrouter-recovery-v3-terminal.json"
)
OPENROUTER_V3_PUBLIC_REQUEST_PATH = REPOSITORY_ROOT / OPENROUTER_V3_PUBLIC_REQUEST_RELATIVE
OPENROUTER_V3_PROTECTED_ROOT = REPOSITORY_ROOT / OPENROUTER_V3_PROTECTED_ROOT_RELATIVE
OPENROUTER_V3_TERMINAL_OUTPUT = REPOSITORY_ROOT / OPENROUTER_V3_TERMINAL_RELATIVE

__all__ = [
    "OPENROUTER_V2_PUBLIC_PACKET_PATH",
    "OPENROUTER_V2_PUBLIC_PACKET_RELATIVE",
    "OPENROUTER_V3_PROTECTED_ROOT",
    "OPENROUTER_V3_PROTECTED_ROOT_RELATIVE",
    "OPENROUTER_V3_PUBLIC_REQUEST_PATH",
    "OPENROUTER_V3_PUBLIC_REQUEST_RELATIVE",
    "OPENROUTER_V3_SNAPSHOT_PATH",
    "OPENROUTER_V3_TERMINAL_OUTPUT",
    "OPENROUTER_V3_TERMINAL_RELATIVE",
    "REPOSITORY_ROOT",
]
