from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from itda.db.session import create_database_engine, create_session_factory
from itda.db.source_snapshot_repositories import SourceSnapshotRepository
from tests.integration.test_recommendation_runs import _migrate, _persist_profile
from tests.unit.test_source_snapshot_repository import binding, bundle


def test_postgres_runtime_can_insert_read_but_not_mutate_source_snapshots(
    postgres_harness: object,
) -> None:
    _migrate(postgres_harness)
    runtime = create_database_engine(postgres_harness.dsns["runtime"])
    admin = create_database_engine(postgres_harness.dsns["admin"])
    repo = SourceSnapshotRepository(create_session_factory(runtime))
    digest = repo.put_source({"provider": "KorWithService2", "place_id": "place:one", "facts": {}})
    assert repo.get_source(digest)["provider"] == "KorWithService2"
    assessed = repo.put_assessment(bundle())
    assert repo.get_assessment(assessed) == bundle()
    for engine in (runtime, admin):
        for statement in (
            "UPDATE app.tourism_source_snapshots SET payload='{}'::jsonb",
            "DELETE FROM app.place_assessment_snapshots",
        ):
            with pytest.raises(DBAPIError), engine.begin() as connection:
                connection.execute(text(statement))
    runtime.dispose()
    admin.dispose()


def test_postgres_run_binding_checks_owner_alias_membership_and_atomicity(
    postgres_harness: object,
) -> None:
    _migrate(postgres_harness)
    runtime = create_database_engine(postgres_harness.dsns["runtime"])
    factory = create_session_factory(runtime)
    repo = SourceSnapshotRepository(factory)
    profile = _persist_profile(runtime, "source-storage-profile")
    digest = repo.put_source({"place_id": "place:one", "value": 1})
    first = binding(digest, preference_profile_id=profile.profile_id)
    with factory.begin() as session:
        # This fixture exercises the actual additive storage constraints. The
        # full recommendation application tracer is tested separately.
        session.execute(
            text("""INSERT INTO app.recommendation_runs
            (run_id, request_id, preference_profile_id, input_digest, release_sha256,
             canonical_membership_sha256, config_sha256, kernel_version, receipt_sha256,
             receipt, created_at)
            VALUES (:run,:request,:owner,:input,:release,:membership,:config,'fixture',:receipt,
                    '{}'::jsonb,:created)"""),
            {
                "run": first.run_id,
                "request": first.request_id,
                "owner": profile.profile_id,
                "input": "a" * 64,
                "release": first.raw_release_sha256,
                "membership": "d" * 64,
                "config": "e" * 64,
                "receipt": "f" * 64,
                "created": first.created_at,
            },
        )
        repo.bind_run_in_session(session, first)
    assert repo.get_run_binding(first.run_id) == first
    alias = binding(digest, preference_profile_id=profile.profile_id, request_id="request:two")
    with pytest.raises(DBAPIError):
        repo.bind_run(alias)  # Alias has not been authorized in the existing request table.
    with factory.begin() as session:
        session.execute(
            text("""INSERT INTO app.recommendation_request_bindings
            (request_id,run_id,preference_profile_id,input_digest,created_at)
            VALUES (:request,:run,:owner,:input,:created)"""),
            {
                "request": alias.request_id,
                "run": first.run_id,
                "owner": profile.profile_id,
                "input": "a" * 64,
                "created": first.created_at,
            },
        )
        repo.bind_run_in_session(session, alias)
    assert repo.get_request_binding(alias.request_id) == alias
    with pytest.raises(DBAPIError):
        # Missing parent run is caught at commit by the deferred FK/guard.
        repo.bind_run(binding(digest, run_id="run:missing", request_id="request:missing"))
    runtime.dispose()
