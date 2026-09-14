"""Production initialization with synthetic test evidence and real PostgreSQL CAS."""

from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from itda.cli import deploy_database
from itda.cli import initialize_grounded_release as initial
from itda.contracts.grounded_release import GroundedReleaseCandidate
from itda.contracts.grounded_run import GROUNDED_POLICY
from itda.db.assessment_release import AssessmentReleaseRepository
from itda.db.session import create_database_engine, create_session_factory
from itda.domain.canonical import canonical_sha256
from tests.integration.test_grounded_release_pairs import (
    candidate_fixture as legacy_candidate_fixture,
)
from tests.integration.test_grounded_release_pairs import (
    gate_fixture,
    report_fixtures,
)
from tests.integration.test_national_grounded_migration import national_candidate
from tests.integration.test_recommendation_runs import _migrate


def candidate_fixture(tag=0):
    candidate = national_candidate(80)
    fields = candidate.model_dump(mode="json", exclude={"candidate_sha256"})
    fields["created_at"] = (
        (candidate.created_at + timedelta(seconds=tag)).isoformat().replace("+00:00", "Z")
    )
    return GroundedReleaseCandidate.model_validate(
        fields | {"candidate_sha256": canonical_sha256(fields)}
    )


TABLES = (
    "grounded_release_active",
    "grounded_release_promotions",
    "grounded_promotion_gates",
    "grounded_promotion_reports",
    "grounded_release_candidates",
)


@pytest.fixture(scope="module")
def schema(postgres_harness):
    _migrate(postgres_harness)


@pytest.fixture
def database(schema, postgres_harness):
    with postgres_harness.connect("admin", autocommit=True) as connection:
        connection.execute("TRUNCATE " + ",".join("app." + table for table in TABLES))
    engine = create_database_engine(postgres_harness.dsns["admin"])
    yield (
        AssessmentReleaseRepository(create_session_factory(engine)),
        postgres_harness.dsns["admin"],
    )
    engine.dispose()


def _counts(postgres_harness):
    with postgres_harness.connect("admin") as connection:
        return tuple(
            connection.execute("SELECT count(*) FROM app." + table).fetchone()[0]
            for table in TABLES
        )


def _bundle(directory, *, tag=0, failed=False, config=GROUNDED_POLICY.sha256):
    directory.mkdir(parents=True, exist_ok=True)
    candidate = candidate_fixture(tag)
    reports = report_fixtures(candidate, failed=failed, config=config)
    gate = gate_fixture(candidate, reports)
    candidate_path, gate_path, report_dir = (
        directory / "candidate.json",
        directory / "gate.json",
        directory / "reports",
    )
    candidate_path.write_text(candidate.model_dump_json())
    gate_path.write_text(gate.model_dump_json())
    report_dir.mkdir()
    for report in reports:
        (report_dir / (report.report_sha256 + ".json")).write_text(report.model_dump_json())
    environment = dict(
        zip(
            initial.INITIAL_PATH_ENV, map(str, (candidate_path, gate_path, report_dir)), strict=True
        )
    )
    return environment, candidate, gate, reports


def _publish(store, candidate, *, config=GROUNDED_POLICY.sha256):
    reports = report_fixtures(candidate, config=config)
    gate = gate_fixture(candidate, reports)
    store.stage(candidate)
    for report in reports:
        store.store_report(report)
    generation = store.promote(gate, expected_config_sha256=config)
    return gate, generation


@pytest.mark.parametrize("default_paths", [False, True])
def test_empty_database_initializes_from_complete_reports_and_reads_back(
    database, tmp_path, monkeypatch, default_paths
):
    store, dsn = database
    monkeypatch.chdir(tmp_path)
    directory = initial.DEFAULT_BUNDLE_DIRECTORY if default_paths else tmp_path / "selected"
    environment, candidate, gate, reports = _bundle(directory)
    status = initial.ensure_initial_grounded_release(
        {} if default_paths else environment, admin_dsn=dsn
    )
    assert status.state == "initialized" and status.generation == 1
    assert status.candidate_sha256 == candidate.candidate_sha256
    assert status.gate_sha256 == gate.gate_sha256
    active = store.load_active_record()
    assert active.candidate == candidate and active.gate == gate
    assert store.load_promotion(status.generation) == active
    assert tuple(store.load_report(report.report_sha256) for report in reports) == reports
    assert initial.ensure_initial_grounded_release({}, admin_dsn=dsn).state == "retained"
    assert store.load_active_record().generation == 1


@pytest.mark.parametrize(
    "damage",
    [
        "missing_option",
        "blank_override",
        "missing_report",
        "invalid_report",
        "failed_report",
        "wrong_policy",
        "wrong_candidate",
        "symlink",
        "fifo",
        "oversized",
    ],
)
def test_incomplete_or_invalid_evidence_fails_before_any_mutation(
    database, postgres_harness, tmp_path, damage
):
    _, dsn = database
    environment, _, _, reports = _bundle(
        tmp_path,
        failed=damage == "failed_report",
        config="f" * 64 if damage == "wrong_policy" else GROUNDED_POLICY.sha256,
    )
    report_path = Path(environment[initial.INITIAL_PATH_ENV[2]]) / (
        reports[0].report_sha256 + ".json"
    )
    if damage == "missing_option":
        environment.pop(initial.INITIAL_PATH_ENV[2])
    elif damage == "blank_override":
        environment = {initial.INITIAL_PATH_ENV[0]: " "}
    elif damage == "missing_report":
        report_path.unlink()
    elif damage == "invalid_report":
        report_path.write_text("private-artifact-canary")
    elif damage == "wrong_candidate":
        Path(environment[initial.INITIAL_PATH_ENV[0]]).write_text(
            candidate_fixture(1).model_dump_json()
        )
    elif damage == "symlink":
        target = tmp_path / "report-target"
        report_path.rename(target)
        report_path.symlink_to(target)
    elif damage == "fifo":
        report_path.unlink()
        os.mkfifo(report_path)
    elif damage == "oversized":
        with report_path.open("wb") as output:
            output.truncate(32 * 1024 * 1024 + 1)
    assert _counts(postgres_harness) == (0, 0, 0, 0, 0)
    with pytest.raises(RuntimeError) as captured:
        initial.ensure_initial_grounded_release(environment, admin_dsn=dsn)
    assert str(captured.value) == "initial grounded release initialization rejected"
    assert captured.value.__suppress_context__
    assert _counts(postgres_harness) == (0, 0, 0, 0, 0)


def test_existing_newer_active_is_kept_without_bundle_files(
    database, postgres_harness, tmp_path, monkeypatch
):
    store, dsn = database
    candidate = candidate_fixture(999)
    gate, generation = _publish(store, candidate)
    before = _counts(postgres_harness)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        initial, "_read_regular", lambda *_a, **_kw: pytest.fail("read bundle despite active pair")
    )
    status = initial.ensure_initial_grounded_release({}, admin_dsn=dsn)
    assert status == initial.InitialGroundedReleaseStatus(
        "retained", candidate.candidate_sha256, gate.gate_sha256, generation
    )
    assert _counts(postgres_harness) == before


def test_incompatible_existing_policy_rejects_without_replacing_active(
    database, postgres_harness, tmp_path
):
    store, dsn = database
    old = candidate_fixture(100)
    _publish(store, old, config="f" * 64)
    environment, _, _, _ = _bundle(tmp_path)
    before = _counts(postgres_harness)
    with pytest.raises(RuntimeError, match="initial grounded release initialization rejected"):
        initial.ensure_initial_grounded_release(environment, admin_dsn=dsn)
    assert store.load_active_record().candidate == old
    assert _counts(postgres_harness) == before


def test_concurrent_publication_wins_over_bundled_initial_candidate(
    database, tmp_path, monkeypatch
):
    store, dsn = database
    environment, bundled, _, _ = _bundle(tmp_path)
    winner = candidate_fixture(1000)
    winner_reports = report_fixtures(winner)
    winner_gate = gate_fixture(winner, winner_reports)
    original_promote = AssessmentReleaseRepository.promote
    raced = False

    def promote_after_other_writer(self, gate, **kwargs):
        nonlocal raced
        assert not raced and kwargs["expected_active_sha256"] is None
        raced = True
        store.stage(winner)
        for report in winner_reports:
            store.store_report(report)
        original_promote(store, winner_gate, expected_active_sha256=None)
        # Execute the actual PostgreSQL compare-and-swap conflict.
        return original_promote(self, gate, **kwargs)

    monkeypatch.setattr(AssessmentReleaseRepository, "promote", promote_after_other_writer)
    status = initial.ensure_initial_grounded_release(environment, admin_dsn=dsn)
    assert raced and status.state == "retained"
    assert status.candidate_sha256 == winner.candidate_sha256
    assert store.load_active_record().candidate == winner
    assert store.load_candidate(bundled.candidate_sha256) == bundled
    assert store.load_promotion(1).candidate == winner
    assert store.load_promotion(2) is None


@pytest.mark.parametrize("reject", [False, True])
def test_deployment_initializes_after_schema_and_prints_only_closed_status(
    monkeypatch, capsys, reject
):
    calls = []
    settings = SimpleNamespace(admin_dsn="private-admin-canary")
    monkeypatch.setattr(deploy_database, "load_settings", lambda: settings)
    monkeypatch.setattr(deploy_database, "provision_roles", lambda _: calls.append("roles"))
    monkeypatch.setattr(deploy_database, "upgrade_schema", lambda _: calls.append("schema"))

    def initialize(environment, *, admin_dsn):
        assert environment is os.environ and admin_dsn == settings.admin_dsn
        calls.append("initial")
        if reject:
            raise RuntimeError("private-artifact-canary")
        return initial.InitialGroundedReleaseStatus("initialized", "a" * 64, "b" * 64, 1)

    monkeypatch.setattr(deploy_database, "ensure_initial_grounded_release", initialize)
    assert deploy_database.main() == (1 if reject else 0)
    assert calls == ["roles", "schema", "initial"]
    output = capsys.readouterr().out
    assert "private" not in output
    assert ("Grounded recommendation release is ready (initialized)." in output) != reject


def test_retired_active_is_not_retained_when_national_current_is_absent(
    database, tmp_path, monkeypatch
):
    store, dsn = database
    retired = legacy_candidate_fixture()
    _publish(store, retired)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(RuntimeError, match="initial grounded release initialization rejected"):
        initial.ensure_initial_grounded_release({}, admin_dsn=dsn)
    assert store.load_active_record().candidate == retired


def test_explicit_retired_bundle_cannot_initialize_empty_database(
    database, postgres_harness, tmp_path
):
    _, dsn = database
    environment, _, _, _ = _bundle(tmp_path)
    Path(environment[initial.INITIAL_PATH_ENV[0]]).write_text(
        legacy_candidate_fixture().model_dump_json()
    )
    with pytest.raises(RuntimeError, match="initial grounded release initialization rejected"):
        initial.ensure_initial_grounded_release(environment, admin_dsn=dsn)
    assert _counts(postgres_harness) == (0, 0, 0, 0, 0)


def test_old_default_bundle_is_never_fallback_when_national_current_is_missing(
    database, postgres_harness, tmp_path, monkeypatch
):
    _, dsn = database
    monkeypatch.chdir(tmp_path)
    _bundle(Path("artifacts/public/catalog/grounded-bootstrap"))
    with pytest.raises(RuntimeError, match="initial grounded release initialization rejected"):
        initial.ensure_initial_grounded_release({}, admin_dsn=dsn)
    assert _counts(postgres_harness) == (0, 0, 0, 0, 0)
