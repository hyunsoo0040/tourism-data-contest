"""Plan 02-29 migration and branch-consumer contract without a live database."""

from __future__ import annotations

from contextlib import nullcontext
from pathlib import Path

import pytest

from itda.cli.manage_real_manifest import verify_predecessor
from itda.contracts.real_manifest_seal import (
    LiveSchemaClassification,
    SchemaInspection,
    classify_live_schema,
    execute_schema_action,
    inspect_schema_twice,
)
from itda.domain.canonical import canonical_sha256

ROOT = Path(__file__).resolve().parents[3]
MIGRATION = ROOT / "backend/migrations/versions/0003_real_manifest.py"


def _inspection(head: str | None, *, exact: bool = True) -> SchemaInspection:
    heads = () if head is None else (head,)
    fields = {
        "heads": list(heads),
        "schema_objects_sha256": "d" * 64,
        "constraints_sha256": "e" * 64,
        "functions_sha256": "f" * 64,
        "acls_sha256": "0" * 64,
    }
    aggregate = canonical_sha256(fields)
    return SchemaInspection(
        heads=heads,
        schema_objects_sha256="d" * 64,
        constraints_sha256="e" * 64,
        functions_sha256="f" * 64,
        acls_sha256="0" * 64,
        schema_contract_sha256=aggregate,
        expected_schema_contract_sha256=aggregate if exact else "b" * 64,
        effective_role="phase2-schema-admin",
        connection_binding_sha256="c" * 64,
    )


class RecordingConnection:
    def __init__(self, before: SchemaInspection, after: SchemaInspection | None = None) -> None:
        self.before = before
        self.after = after or before
        self.inspections = 0
        self.mutations = 0
        self.read_locks = 0

    def read_lock(self):
        self.read_locks += 1
        return nullcontext()

    def mutation_lock(self):
        return nullcontext()

    def inspect(self) -> SchemaInspection:
        self.inspections += 1
        return self.before if self.inspections == 1 else self.after

    def upgrade_exactly_one(self, expected_from: str, target: str) -> None:
        assert (expected_from, target) == ("0002_split_boundaries", "0003_real_manifest")
        self.mutations += 1


def test_migration_is_exact_additive_0002_to_0003_contract() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    assert 'revision = "0003_real_manifest"' in source
    assert 'down_revision = "0002_split_boundaries"' in source
    assert "seal_real_manifest_v1" in source
    assert "lookup_real_manifest_seal_v1" in source
    assert "SECURITY DEFINER" in source
    assert "REVOKE ALL" in source
    assert "UPDATE " not in source.upper()
    assert "DELETE " not in source.upper()
    assert "ON DELETE CASCADE" not in source.upper()


def test_predecessor_verifier_accepts_plan_backend_relative_path() -> None:
    binding = verify_predecessor(ROOT, Path("migrations/versions/0002_split_boundaries.py"))
    assert binding["predecessor_sha256"] == (
        "ecb7685720404a7f5ad17a776f16372542068e4aa7d7ead35e45723a450d4b1b"
    )
    assert binding["predecessor_blob_sha1"] == "27f828d031d7f5b08ea4b41a5639b1c5dd73af20"


def test_live_classification_is_closed_and_exact() -> None:
    assert classify_live_schema(_inspection(None)) is LiveSchemaClassification.ABSENT
    assert classify_live_schema(_inspection("0001_app_profiles")) is LiveSchemaClassification.OLDER
    assert (
        classify_live_schema(_inspection("0002_split_boundaries"))
        is LiveSchemaClassification.EXACT_0002
    )
    assert (
        classify_live_schema(_inspection("0003_real_manifest"))
        is LiveSchemaClassification.EXACT_0003
    )
    assert (
        classify_live_schema(_inspection("0002_split_boundaries", exact=False))
        is LiveSchemaClassification.DIVERGENT
    )
    multi = _inspection("0002_split_boundaries").model_copy(
        update={"heads": ("0002_split_boundaries", "other")}
    )
    assert classify_live_schema(multi) is LiveSchemaClassification.MULTI_HEAD


def test_apply_mutates_once_only_from_exact_0002_and_reinspects() -> None:
    connection = RecordingConnection(
        _inspection("0002_split_boundaries"), _inspection("0003_real_manifest")
    )
    result = execute_schema_action(connection, action="schema-apply-0003")
    assert result.classification is LiveSchemaClassification.EXACT_0003
    assert result.mutation_count == 1
    assert connection.mutations == 1
    assert connection.inspections == 2


def test_verify_exact_0003_is_zero_mutation_and_never_falls_through() -> None:
    connection = RecordingConnection(_inspection("0003_real_manifest"))
    result = execute_schema_action(connection, action="schema-verify-0003")
    assert result.classification is LiveSchemaClassification.EXACT_0003
    assert result.mutation_count == 0
    assert connection.mutations == 0
    assert connection.inspections == 2


@pytest.mark.parametrize(
    "head,action",
    [
        (None, "schema-apply-0003"),
        ("0001_app_profiles", "schema-apply-0003"),
        ("unexpected", "schema-apply-0003"),
        ("0002_split_boundaries", "schema-verify-0003"),
        ("0003_real_manifest", "schema-apply-0003"),
    ],
)
def test_unsafe_or_wrong_branch_has_zero_mutation(head: str | None, action: str) -> None:
    connection = RecordingConnection(_inspection(head))
    with pytest.raises(ValueError):
        execute_schema_action(connection, action=action)  # type: ignore[arg-type]
    assert connection.mutations == 0


def test_request_inspection_is_stable_twice_under_one_read_lock() -> None:
    connection = RecordingConnection(_inspection("0002_split_boundaries"))
    assert inspect_schema_twice(connection) == _inspection("0002_split_boundaries")
    assert connection.read_locks == 1
    assert connection.inspections == 2

    drifting = RecordingConnection(
        _inspection("0002_split_boundaries"), _inspection("0003_real_manifest")
    )
    with pytest.raises(ValueError, match="changed"):
        inspect_schema_twice(drifting)
