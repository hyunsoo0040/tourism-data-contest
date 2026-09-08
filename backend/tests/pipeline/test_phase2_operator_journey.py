"""Offline operator-journey contract for DATA-05 through DATA-08.

The journey is collect -> audit -> catalog approval -> deterministic split ->
separate split approval -> restricted seal. It uses frozen fixtures only.
"""

from __future__ import annotations

import importlib
import importlib.util
from types import ModuleType

import pytest

ENTRYPOINTS = {
    "collect": "itda.cli.collect_catalog",
    "audit": "itda.cli.export_catalog_audit",
    "catalog_approval": "itda.cli.approve_catalog",
    "split_approval": "itda.cli.approve_split",
    "restricted_seal": "itda.cli.seal_catalog_manifest",
}
REQUIRED_FLAGS = {
    "collect": ("--request-plan", "--output-root"),
    "audit": ("--audit-json", "--output-root", "--format"),
    "catalog_approval": ("--review-request", "--adjudication", "--confirm-catalog-sha256"),
    "split_approval": ("--restricted-manifest", "--confirm-sha256"),
    "restricted_seal": (
        "--manifest",
        "--catalog-approval",
        "--split-approval",
        "--confirm-sha256",
        "--connection-env",
        "--connection-label",
        "--verify-existing",
    ),
}


def _entrypoints_or_skip() -> dict[str, ModuleType]:
    missing = [
        module_name for module_name in ENTRYPOINTS.values() if not _module_exists(module_name)
    ]
    if missing:
        pytest.skip("Phase 2 operator entrypoints are implemented in Plans 02-05 through 02-12")
    return {name: importlib.import_module(module_name) for name, module_name in ENTRYPOINTS.items()}


def _module_exists(module_name: str) -> bool:
    return importlib.util.find_spec(module_name) is not None


def test_operator_journey_has_frozen_offline_entrypoints_and_stable_flags() -> None:
    entrypoints = _entrypoints_or_skip()
    for name, module in entrypoints.items():
        assert callable(module.main)
        parser = module.build_parser()
        help_text = parser.format_help()
        for flag in REQUIRED_FLAGS[name]:
            assert flag in help_text
        assert "http://" not in help_text
        assert "https://" not in help_text
        assert "--live" not in help_text


def test_catalog_and_split_approval_are_distinct_operator_actions() -> None:
    entrypoints = _entrypoints_or_skip()
    assert entrypoints["catalog_approval"].main is not entrypoints["split_approval"].main
    catalog_help = entrypoints["catalog_approval"].build_parser().format_help()
    split_help = entrypoints["split_approval"].build_parser().format_help()
    assert "--confirm-catalog-sha256" in catalog_help
    assert "--confirm-sha256" in split_help
    assert "--catalog-approval" in split_help


def test_restricted_seal_outcome_uses_named_connection_reference_only() -> None:
    entrypoints = _entrypoints_or_skip()
    help_text = entrypoints["restricted_seal"].build_parser().format_help()
    assert "--connection-env" in help_text
    assert "--connection-label" in help_text
    assert "--verify-existing" in help_text
    assert "--dsn" not in help_text


def test_phase2_operator_journey_reports_missing_entrypoints() -> None:
    if any(not _module_exists(module_name) for module_name in ENTRYPOINTS.values()):
        pytest.fail("PHASE2-MISSING:operator-journey-entrypoints", pytrace=False)
    for module_name in ENTRYPOINTS.values():
        importlib.import_module(module_name)
