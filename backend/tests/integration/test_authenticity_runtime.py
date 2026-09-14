"""Real PostgreSQL: migration, limited runtime grants, owner isolation and pinned replay."""

from datetime import UTC, datetime

import pytest
from alembic import command
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from itda.authenticity.ranking import rank
from itda.authenticity.release import build_release, load_release
from itda.authenticity.repository import (
    OwnershipError,
    Repository,
    RequestConflict,
    install_release,
)
from itda.authenticity.service import Service
from itda.db.session import create_database_engine
from tests.authenticity.test_intent_and_ranking import assessment, intent
from tests.integration.test_daily_glm_refresh_migration import _config


def test_authenticity_postgres_release_sessions_and_replay(postgres_harness, tmp_path):
    config = _config(postgres_harness)
    command.upgrade(config, "head")
    admin = create_database_engine(postgres_harness.dsns["admin"])
    runtime = create_database_engine(postgres_harness.dsns["runtime"])
    repository = Repository(runtime)
    try:
        rows = tuple(assessment(i) for i in range(1, 7))
        directory = tmp_path / "release"
        release = build_release(
            assessments=rows,
            directory=directory,
            expected_ids=tuple(a.source.place.place_id for a in rows),
            parent_manifest_sha256="a" * 64,
            scope="DEVELOPMENT",
            created_at=datetime.now(UTC),
        )
        assert load_release(directory)[0] == release
        install_release(admin, directory, expected_previous=None, activate=True)
        assert repository.active_release() == release
        pinned, read = repository.get_release(release.release_sha256)
        assert pinned == release and read == rows
        with pytest.raises(DBAPIError):
            install_release(runtime, directory, expected_previous=None, activate=False)
        with pytest.raises(RequestConflict):
            install_release(admin, directory, expected_previous=None, activate=True)
        with admin.begin() as connection, pytest.raises(DBAPIError):
            connection.execute(text("UPDATE app.authenticity_assessments SET place_id=place_id"))
        first = repository.create_session()
        second = repository.create_session()
        sid = repository.session(first["token"])
        other = repository.session(second["token"])
        profile = repository.put_intent(sid, intent({"H.a": 4}))
        assert repository.get_intent(sid, profile.profile_id) == profile
        with pytest.raises(OwnershipError):
            repository.get_intent(other, profile.profile_id)
        run = rank(
            assessments=read, intent=profile, created_at=datetime.now(UTC), request_id="new-run"
        )
        stored = repository.put_run(sid, "new-run", release, run)
        assert stored == run
        assert repository.get_run(sid, run["run_sha256"])["payload"] == run
        replacement_rows = tuple(assessment(i, history=1 if i == 1 else 4) for i in range(1, 7))
        replacement_dir = tmp_path / "replacement"
        replacement = build_release(
            assessments=replacement_rows,
            directory=replacement_dir,
            expected_ids=tuple(a.source.place.place_id for a in replacement_rows),
            parent_manifest_sha256="b" * 64,
            scope="DEVELOPMENT",
            created_at=datetime.now(UTC),
        )
        install_release(
            admin, replacement_dir, expected_previous=release.release_sha256, activate=True
        )
        service = Service(repository, allow_development=True)
        assert service.run(sid, run["run_sha256"]) == run
        newer = service.create_run(sid, profile.profile_id, "after-promotion").model_dump(
            mode="json"
        )
        assert newer["assessment_set_sha256"] != run["assessment_set_sha256"]
        install_release(
            admin, directory, expected_previous=replacement.release_sha256, activate=True
        )
        assert repository.active_release() == release
        assert service.run(sid, run["run_sha256"]) == run
        assert (
            service.run(sid, newer["run_sha256"])["assessment_set_sha256"]
            == newer["assessment_set_sha256"]
        )
        with pytest.raises(OwnershipError):
            repository.get_run(other, run["run_sha256"])
        pid = run["items"][0]["place_id"]
        repository.save(sid, run["run_sha256"], pid, saved=True)
        repository.save(sid, run["run_sha256"], pid, saved=True)
        assert len(repository.saved(sid)) == 1
        assert repository.saved(other) == []
        repository.feedback(sid, run["run_sha256"], pid, {"test_only": True, "visited": False})
        repository.delete_session(sid)
        with pytest.raises(OwnershipError):
            repository.session(first["token"])
        assert repository.saved(sid) == []
        assert repository.active_release() == release
    finally:
        runtime.dispose()
        admin.dispose()
