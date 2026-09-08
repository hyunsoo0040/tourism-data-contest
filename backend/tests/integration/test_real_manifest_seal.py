"""Wave 0 PostgreSQL/CLI contract for DATA-08 restricted real-manifest sealing."""

from __future__ import annotations

import importlib
import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

CAPABILITY_MODULE = "itda.cli.seal_catalog_manifest"
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
MIGRATION_PATH = REPOSITORY_ROOT / "backend/migrations/versions/0003_real_catalog_manifest.py"


def _capability_or_skip() -> ModuleType:
    if importlib.util.find_spec(CAPABILITY_MODULE) is None:
        pytest.skip("restricted real sealer is implemented in Plan 02-12")
    return importlib.import_module(CAPABILITY_MODULE)


def test_real_sealer_cli_has_only_named_connection_reference_surface() -> None:
    capability = _capability_or_skip()
    help_text = capability.build_parser().format_help()
    for flag in (
        "--manifest",
        "--catalog-approval",
        "--split-approval",
        "--confirm-sha256",
        "--connection-env",
        "--connection-label",
        "--verify-existing",
    ):
        assert flag in help_text
    assert "--dsn" not in help_text


def test_uncertain_commit_requires_read_only_lookup_before_retry() -> None:
    capability = _capability_or_skip()
    connection = capability.RecordingConnection(
        seal_outcome=capability.CommitOutcome.UNCERTAIN,
        lookup_outcome=capability.LookupOutcome.EXACT_MATCH,
    )
    result = capability.seal_catalog_manifest(
        capability.synthetic_seal_request(),
        connection=connection,
    )
    assert result.status == "VERIFIED_SEALED"
    assert connection.calls == ("seal_catalog_manifest_v1", "lookup_catalog_manifest_seal_v1")
    assert connection.mutation_count == 1


@pytest.mark.skipif(
    not MIGRATION_PATH.exists(), reason="migration 0003 is implemented in Plan 02-12"
)
def test_migration_declares_additive_lifecycle_and_insert_only_boundaries() -> None:
    source = MIGRATION_PATH.read_text(encoding="utf-8")
    assert 'revision = "0003_real_catalog_manifest"' in source
    assert 'down_revision = "0002_split_boundaries"' in source
    assert "seal_catalog_manifest_v1" in source
    assert "lookup_catalog_manifest_seal_v1" in source
    assert "SECURITY DEFINER" in source
    assert "REVOKE ALL" in source
    assert "UPDATE " not in source.upper()
    assert "DELETE " not in source.upper()
    assert "ON DELETE CASCADE" not in source.upper()


@pytest.mark.skipif(
    not MIGRATION_PATH.exists(), reason="migration 0003 is implemented in Plan 02-12"
)
def test_restricted_schema_denies_hostile_update_delete_truncate_and_grants(
    postgres_harness: object,
) -> None:
    capability = _capability_or_skip()
    capability.upgrade_from_blank_and_phase1_head(postgres_harness)
    capability.assert_hostile_role_matrix(
        postgres_harness,
        denied_statements=(
            "UPDATE blind_eval.catalog_manifest_seals SET manifest_sha256 = repeat('0', 64)",
            "DELETE FROM blind_eval.catalog_manifest_seals",
            "TRUNCATE blind_eval.catalog_manifest_seals CASCADE",
            "GRANT SELECT ON blind_eval.catalog_manifest_members TO PUBLIC",
        ),
    )
    capability.downgrade_only_phase2_and_reupgrade(postgres_harness)


def test_missing_restricted_seal_is_controlled_red() -> None:
    if importlib.util.find_spec(CAPABILITY_MODULE) is None:
        pytest.fail("PHASE2-MISSING:restricted-seal", pytrace=False)
    importlib.import_module(CAPABILITY_MODULE)
