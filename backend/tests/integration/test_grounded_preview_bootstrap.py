"""Optional offline bootstrap uses generated administrator authority and real gates."""

from __future__ import annotations

import json
import os

import pytest

from itda.cli import e2e_runtime
from itda.cli import grounded_preview_bootstrap as preview
from itda.db.assessment_release import AssessmentReleaseRepository
from itda.db.session import create_database_engine, create_session_factory
from tests.integration.test_grounded_release_pairs import (
    candidate_fixture,
    gate_fixture,
    report_fixtures,
)
from tests.integration.test_recommendation_runs import _migrate


@pytest.fixture(scope="module")
def pair(postgres_harness):
    _migrate(postgres_harness)
    engine = create_database_engine(postgres_harness.dsns["admin"])
    yield (
        AssessmentReleaseRepository(create_session_factory(engine)),
        postgres_harness.dsns["admin"],
    )
    engine.dispose()


@pytest.fixture
def artifact_paths(tmp_path):
    candidate = candidate_fixture()
    reports = report_fixtures(candidate)
    gate = gate_fixture(candidate, reports)
    candidate_path = tmp_path / "candidate.json"
    candidate_path.write_text(candidate.model_dump_json())
    gate_path = tmp_path / "gate.json"
    gate_path.write_text(gate.model_dump_json())
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    for report in reports:
        (report_dir / (report.report_sha256 + ".json")).write_text(report.model_dump_json())
    env = dict(
        zip(
            preview.BOOTSTRAP_PATH_ENV,
            map(str, (candidate_path, gate_path, report_dir)),
            strict=True,
        )
    )
    env.update(ITDA_NO_NETWORK="1", CI="1")
    return env, candidate, gate, reports


def test_default_has_no_database_or_environment_side_effect(monkeypatch):
    monkeypatch.setattr(
        preview, "create_database_engine", lambda _: pytest.fail("default bootstrap touched DB")
    )
    env = {"ITDA_NO_NETWORK": "1", "ZHIPUAI_API_KEY": "not-forwarded"}
    assert preview.bootstrap_grounded_preview(env, admin_dsn="must-not-be-used") == {}
    assert env == {"ITDA_NO_NETWORK": "1", "ZHIPUAI_API_KEY": "not-forwarded"}


@pytest.mark.parametrize(
    "damage", ["missing_option", "network_enabled", "missing_report", "wrong_candidate", "bad_json"]
)
def test_every_artifact_is_validated_before_any_database_access(
    artifact_paths, monkeypatch, damage
):
    env, candidate, gate, reports = artifact_paths
    monkeypatch.setattr(
        preview, "create_database_engine", lambda _: pytest.fail("invalid artifacts reached DB")
    )
    if damage == "missing_option":
        env.pop(preview.BOOTSTRAP_PATH_ENV[2])
    elif damage == "network_enabled":
        env["ITDA_NO_NETWORK"] = "0"
    elif damage == "missing_report":
        from pathlib import Path

        (Path(env[preview.BOOTSTRAP_PATH_ENV[2]]) / (reports[0].report_sha256 + ".json")).unlink()
    elif damage == "wrong_candidate":
        from pathlib import Path

        Path(env[preview.BOOTSTRAP_PATH_ENV[0]]).write_text(candidate_fixture(1).model_dump_json())
    else:
        from pathlib import Path

        Path(env[preview.BOOTSTRAP_PATH_ENV[1]]).write_text("secret-canary-invalid-json")
    with pytest.raises(RuntimeError) as captured:
        preview.bootstrap_grounded_preview(env, admin_dsn="private-admin-canary")
    assert str(captured.value) == "grounded offline preview bootstrap rejected"
    assert captured.value.__suppress_context__


def test_real_gate_bootstrap_is_idempotent_and_returns_only_offline_child_flags(
    pair, artifact_paths
):
    store, dsn = pair
    env, candidate, gate, _ = artifact_paths
    flags = preview.bootstrap_grounded_preview(env, admin_dsn=dsn)
    assert flags == {
        "ITDA_GROUNDED_RECOMMENDATIONS_ENABLED": "1",
        "ITDA_PHOTO_MOOD_ENABLED": "1",
        "ITDA_TOURISM_ENABLED": "0",
        "ITDA_NO_NETWORK": "1",
    }
    active = store.load_active_record()
    assert active.candidate == candidate and active.gate == gate
    generation = active.generation
    assert preview.bootstrap_grounded_preview(env, admin_dsn=dsn) == flags
    assert store.load_active_record().generation == generation
    assert dsn not in json.dumps(flags)


def test_start_api_injects_verified_flags_without_paths_keys_or_admin_dsn(
    pair, artifact_paths, monkeypatch
):
    store, dsn = pair
    env, candidate, _, _ = artifact_paths
    environment = {
        **e2e_runtime._REQUIRED_ENVIRONMENT,
        **env,
        "ITDA_E2E_RUN_ID": "grounded-bootstrap-test",
        "ZHIPUAI_API_KEY": "forbidden-model-key",
        "TOUR_API_SERVICE_KEY": "forbidden-source-key",
        "ITDA_GROUNDED_CANDIDATE_SHA256": "f" * 64,
    }
    lifecycle = e2e_runtime.DefaultRuntimeLifecycle(environment)
    resources = lifecycle.allocate()
    resources.admin_dsn = dsn
    captured = {}

    def popen(command, **kwargs):
        captured.update(command=command, **kwargs)
        return object()

    monkeypatch.setattr(e2e_runtime.subprocess, "Popen", popen)
    try:
        lifecycle.start_api(resources)
        child = captured["env"]
        assert child["ITDA_DATABASE_URL"] == resources.runtime_dsn
        assert child["ITDA_NO_NETWORK"] == "1" and child["ITDA_TOURISM_ENABLED"] == "0"
        assert child["ITDA_GROUNDED_RECOMMENDATIONS_ENABLED"] == "1"
        assert child["ITDA_PHOTO_MOOD_ENABLED"] == "1" and child["CI"] == "1"
        assert all(key not in child for key in preview.BOOTSTRAP_PATH_ENV)
        assert "ITDA_GROUNDED_CANDIDATE_SHA256" not in child
        assert (
            "forbidden-model-key" not in child.values()
            and "forbidden-source-key" not in child.values()
        )
        assert dsn not in child.values()
        assert store.load_active().candidate_sha256 == candidate.candidate_sha256
    finally:
        lifecycle.begin_cleanup()
        lifecycle.cleanup_private_output(resources)


def test_fresh_default_runtime_migrates_and_verifies_exact_photo_capabilities():
    """Exercise the real supervisor pre-API chain, not the narrower PG fixture."""
    import psycopg

    environment = {
        **os.environ,
        **e2e_runtime._REQUIRED_ENVIRONMENT,
        "ITDA_E2E_RUN_ID": "grounded-full-authority-check",
    }
    # This authority-only boot has no candidate/gate selectors and never starts
    # an API listener; it owns and destroys a separate disposable DB/container.
    for name in preview.BOOTSTRAP_PATH_ENV:
        environment.pop(name, None)
    lifecycle = e2e_runtime.DefaultRuntimeLifecycle(environment)
    resources = lifecycle.allocate()
    composed = False
    try:
        composed = True
        lifecycle.compose_up(resources)
        lifecycle.migrate(resources)
        with psycopg.connect(resources.photo_service_dsn) as connection:
            allowed = [
                "dev_eval." + signature
                for signature in e2e_runtime.PhotoLifecycleGateway._REQUIRED_FUNCTIONS
            ]
            unexpected = connection.execute(
                """SELECT p.oid::regprocedure::text
                FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                WHERE n.nspname='dev_eval' AND has_function_privilege(current_user,p.oid,'EXECUTE')
                AND p.oid<>ALL(%s::regprocedure[])""",
                (allowed,),
            ).fetchall()
            assert unexpected == []
            mood = [signature for signature in allowed if "mood" in signature]
            assert len(mood) == 6
            assert connection.execute(
                "SELECT has_function_privilege(current_user,"
                "'dev_eval.purge_photo_mood_deleted_v1()','EXECUTE')"
            ).fetchone() == (False,)
        lifecycle.verify_runtime_role(resources)
    finally:
        lifecycle.begin_cleanup()
        lifecycle.cleanup_private_output(resources)
        if composed:
            try:
                lifecycle.drop_database_and_role(resources)
            finally:
                lifecycle.compose_down(resources)
