from __future__ import annotations

from datetime import UTC, date, datetime

import psycopg
import pytest
from alembic import command
from psycopg.types.json import Jsonb
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from itda.contracts.mvp_daily_refresh import (
    DAILY_REFRESH_AUTHORITY,
    DAILY_REFRESH_AUTHORITY_V2,
    DailyRefreshRunStatus,
)
from itda.db.mvp_release_overlay import (
    DailyRefreshConflict,
    DailyRefreshStore,
    DailyReleaseOverlayReader,
)
from itda.db.session import sqlalchemy_url_from_dsn
from itda.domain.canonical import canonical_sha256
from itda.pipeline.daily_public_input import build_daily_delta, build_incremental_scoring_plan
from itda.pipeline.daily_refresh import run_daily_refresh
from tests.integration.test_daily_glm_refresh_migration import _config, _service_dsn
from tests.pipeline.test_daily_availability import AvailabilityProvider, content_id
from tests.pipeline.test_daily_public_input import (
    SyntheticDailyProvider,
    SyntheticScoringTransport,
    _bundled_release,
    _snapshot,
)
from tests.pipeline.test_daily_refresh import CATALOG, EVIDENCE, RELATIONS

BASELINE_DATE = date(2026, 8, 31)
FAILED_DATE = date(2026, 8, 29)
CLAIMED_DATE = date(2026, 8, 30)


@pytest.fixture(scope="module")
def availability_db(postgres_harness):
    config = _config(postgres_harness)
    service_dsn = _service_dsn(postgres_harness)
    command.upgrade(config, "0026_daily_glm_availability")
    command.downgrade(config, "0025_daily_glm_operations")
    snapshot = _snapshot(SyntheticDailyProvider(), run_date=BASELINE_DATE)
    fields = snapshot.model_dump(mode="json", exclude={"snapshot_sha256", "excluded"})
    fields.update(
        schema_version="mvp-daily-scoring-input-snapshot.v1",
        authority_sha256=DAILY_REFRESH_AUTHORITY.authority_sha256,
    )
    old = {**fields, "snapshot_sha256": canonical_sha256(fields)}
    with psycopg.connect(service_dsn) as service:
        for day in (FAILED_DATE, CLAIMED_DATE, BASELINE_DATE):
            service.execute(
                "SELECT dev_eval.claim_daily_glm_refresh_v1(%s,%s)",
                (day, DAILY_REFRESH_AUTHORITY.authority_sha256),
            )
            if day == BASELINE_DATE:
                service.execute(
                    "SELECT dev_eval.store_daily_glm_snapshot_v1(%s,%s,%s,%s,%s)",
                    (day, old["snapshot_sha256"], None, old["membership_sha256"], Jsonb(old)),
                )
                service.execute(
                    "SELECT dev_eval.finish_daily_glm_refresh_v1(%s,'BASELINE_RECORDED',0,0,NULL)",
                    (day,),
                )
            else:
                service.execute(
                    "SELECT dev_eval.finish_daily_glm_refresh_v1("
                    "%s,'COLLECTION_INCOMPLETE',0,0,'TOUR_API_COLLECTION_FAILED')",
                    (day,),
                )
    runtime_dsn = postgres_harness.dsns["runtime"]
    with psycopg.connect(runtime_dsn) as runtime:
        claimed = runtime.execute(
            "SELECT command_id FROM dev_eval.request_daily_glm_recollection_v1(%s,%s)",
            (CLAIMED_DATE, "old-policy-claimed-command"),
        ).fetchone()[0]
    with psycopg.connect(service_dsn) as service:
        assert (
            service.execute(
                "SELECT command_id FROM dev_eval.claim_daily_glm_recollection_v1(15)"
            ).fetchone()[0]
            == claimed
        )
    command.upgrade(config, "0026_daily_glm_availability")
    service_engine = create_engine(sqlalchemy_url_from_dsn(service_dsn))
    runtime_engine = create_engine(sqlalchemy_url_from_dsn(runtime_dsn))
    store = DailyRefreshStore(sessionmaker(service_engine))
    reader = DailyReleaseOverlayReader(sessionmaker(runtime_engine))
    yield postgres_harness, service_dsn, store, reader, old, claimed
    service_engine.dispose()
    runtime_engine.dispose()


def refresh(store, reader, day, provider, transport=None):
    def scorer():
        if transport is None:
            raise AssertionError("0-call 경로에서 GLM 객체를 생성했습니다")
        return transport

    return run_daily_refresh(
        run_date=day,
        collected_at=datetime.combine(day, datetime.min.time(), tzinfo=UTC),
        catalog=CATALOG,
        evidence_inventory=EVIDENCE,
        relations=RELATIONS,
        provider=provider,
        store=store,
        active_release_resolver=lambda: reader.active_release() or _bundled_release(),
        scoring_transport_factory=scorer,
    )


def test_upgrade_preserves_history_and_fences_old_writers(availability_db):
    harness, service_dsn, store, reader, old, _ = availability_db
    assert store.baseline_snapshot().model_dump(mode="json") == old
    assert store.latest_snapshot().snapshot_sha256 == old["snapshot_sha256"]
    history = {
        e.run_date: e for e in reader.execution_history(days=30) if e.execution_sequence == 0
    }
    assert history[FAILED_DATE].available_count is None
    assert history[FAILED_DATE].authority_sha256 == DAILY_REFRESH_AUTHORITY.authority_sha256
    assert history[BASELINE_DATE].available_count == 100
    assert history[BASELINE_DATE].snapshot_sha256 == old["snapshot_sha256"]
    for dsn in (service_dsn, harness.dsns["runtime"]):
        with psycopg.connect(dsn) as connection:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    "SELECT dev_eval.claim_daily_glm_refresh_v1(%s,%s)",
                    (date(2026, 9, 20), DAILY_REFRESH_AUTHORITY.authority_sha256),
                )
            connection.rollback()
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                connection.execute("UPDATE dev_eval.daily_glm_refresh_runs SET call_count=0")
            connection.rollback()
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                connection.execute(
                    "SELECT dev_eval.require_daily_availability_run_v2(%s)", (BASELINE_DATE,)
                )
    with pytest.raises(DailyRefreshConflict):
        store.claim(
            run_date=date(2026, 9, 20), authority_sha256=DAILY_REFRESH_AUTHORITY.authority_sha256
        )


def test_zero_call_publish_scoring_reappearance_and_safe_projection(availability_db):
    harness, service_dsn, store, reader, old, _ = availability_db
    first, second = [p.place_id for p in CATALOG.places[:2]]
    outcome = refresh(store, reader, date(2026, 9, 1), AvailabilityProvider(unavailable=[first]))
    assert outcome.status == "RELEASE_ACTIVATED"
    assert outcome.call_count == 0
    first_release = reader.active_release()
    assert first_release.published_count == 99
    assert first_release.excluded[0].place_id == first
    detail = reader.execution_detail(run_date=date(2026, 9, 1), execution_sequence=0)
    assert detail.execution.available_count == 99
    assert detail.execution.information_unavailable_count == 1
    assert detail.execution.event_ended_count == 0
    assert detail.excluded[0].place_id == first
    assert set(detail.excluded[0].model_dump()) == {
        "place_id",
        "content_id",
        "state",
        "safe_reason",
        "event_end_date",
        "place_name_ko",
    }
    assert reader.operations_overview().execution.available_count == 99
    with psycopg.connect(service_dsn) as service:
        assert service.execute(
            "SELECT dev_eval.read_active_daily_scored_release_v2()"
        ).fetchone() == (None,)
        assert (
            service.execute("SELECT dev_eval.read_latest_daily_glm_snapshot_v1()").fetchone()[0]
            == old
        )
    outcome = refresh(
        store,
        reader,
        date(2026, 9, 2),
        AvailabilityProvider(unavailable=[first], metadata_version="2"),
    )
    assert outcome.status == "NO_CHANGES"
    assert reader.active_release() == first_release
    transport = SyntheticScoringTransport()
    outcome = refresh(
        store, reader, date(2026, 9, 3), AvailabilityProvider(unavailable=[second]), transport
    )
    assert outcome.status == "RELEASE_ACTIVATED"
    assert outcome.call_count == 1
    assert set(transport.calls) == {first}
    active = reader.active_release()
    scored = next(p for p in active.profile_entries if p.profile.place_id == first)
    assert scored.lineage.origin == "DAILY_GLM"
    assert active.previous_release_sha256 == first_release.release_sha256
    with pytest.raises(DailyRefreshConflict):
        store.activate(
            run_date=date(2026, 9, 3),
            release_sha256=active.release_sha256,
            expected_current=first_release.release_sha256,
        )
    with harness.connect("admin") as admin:
        assert admin.execute(
            "SELECT count(*) FROM dev_eval.daily_glm_scoring_plans WHERE run_date='2026-09-01'"
        ).fetchone() == (0,)


def test_plan_binding_and_available_gate_are_enforced_in_sql(availability_db):
    _, service_dsn, store, reader, _, _ = availability_db
    previous = store.latest_snapshot()
    target = CATALOG.places[0].place_id
    absent = CATALOG.places[1].place_id
    day = date(2026, 9, 4)
    assert store.claim(run_date=day, authority_sha256=DAILY_REFRESH_AUTHORITY_V2.authority_sha256)
    snapshot = _snapshot(
        AvailabilityProvider(unavailable=[absent], changed_content_id=content_id(target)),
        run_date=day,
        previous_snapshot_sha256=previous.snapshot_sha256,
    )
    store.store_snapshot(snapshot)
    delta = build_daily_delta(previous, snapshot)
    plan = build_incremental_scoring_plan(
        snapshot=snapshot, delta=delta, scoring_place_ids=(target,)
    )
    wrong = plan.model_dump(mode="json", exclude={"plan_sha256"})
    wrong["scoring_place_ids"] = [absent]
    wrong["plan_sha256"] = canonical_sha256(wrong)
    with psycopg.connect(service_dsn) as service, pytest.raises(psycopg.errors.CheckViolation):
        service.execute(
            "SELECT dev_eval.store_daily_glm_scoring_plan_v2(%s,%s,%s,%s)",
            (day, wrong["plan_sha256"], snapshot.snapshot_sha256, Jsonb(wrong)),
        )
    store.store_plan(plan)
    from itda.pipeline.daily_incremental_scoring import execute_incremental_scoring
    from itda.pipeline.daily_scored_release import materialize_daily_scored_release

    synthetic = execute_incremental_scoring(
        snapshot=snapshot,
        plan=plan,
        catalog_sha256=CATALOG.catalog_sha256,
        transport=SyntheticScoringTransport(),
        reserve_call=lambda event: None,
    )
    unreserved = materialize_daily_scored_release(
        previous_release=reader.active_release(),
        previous_snapshot=previous,
        snapshot=snapshot,
        delta=delta,
        catalog=CATALOG,
        relations=RELATIONS,
        results=tuple(synthetic.results.values()),
        failures={},
        created_at=datetime.combine(day, datetime.min.time(), tzinfo=UTC),
        scoring_place_ids=(target,),
    )
    with pytest.raises(DailyRefreshConflict):
        store.publish(unreserved)
    with psycopg.connect(service_dsn) as service:
        for place, request, attempt in [
            (absent, plan.request_sha256[0], 1),
            (target, "f" * 64, 1),
            (target, plan.request_sha256[0], 2),
        ]:
            with pytest.raises(psycopg.errors.CheckViolation):
                service.execute(
                    "SELECT dev_eval.reserve_daily_glm_call_v2(%s,%s,%s,%s,%s)",
                    (day, plan.plan_sha256, place, request, attempt),
                )
            service.rollback()
        assert service.execute(
            "SELECT dev_eval.reserve_daily_glm_call_v2(%s,%s,%s,%s,1)",
            (day, plan.plan_sha256, target, plan.request_sha256[0]),
        ).fetchone() == (1,)
        service.execute(
            "SELECT dev_eval.finish_daily_glm_attempt_v2(%s,%s,1,'FAILED','GLM_TIMEOUT',NULL)",
            (day, target),
        )
        assert service.execute(
            "SELECT dev_eval.reserve_daily_glm_call_v2(%s,%s,%s,%s,2)",
            (day, plan.plan_sha256, target, plan.request_sha256[0]),
        ).fetchone() == (2,)
        service.execute(
            "SELECT dev_eval.finish_daily_glm_attempt_v2(%s,%s,2,'FAILED','GLM_TIMEOUT',NULL)",
            (day, target),
        )
    store.finish(
        run_date=day,
        status=DailyRefreshRunStatus.SCORING_FAILED,
        changed_count=1,
        failed_count=1,
        safe_reason="SYNTHETIC_TEST_COMPLETE",
    )
    previous_active = reader.active_release()
    absent_ids = [p.place_id for p in CATALOG.places[79:]]
    outcome = refresh(store, reader, date(2026, 9, 5), AvailabilityProvider(unavailable=absent_ids))
    assert outcome.status == "RELEASE_REJECTED"
    assert outcome.call_count == 0
    assert reader.active_release() == previous_active
    detail = reader.execution_detail(run_date=date(2026, 9, 5), execution_sequence=0)
    assert detail.execution.available_count == 79
    assert len(detail.excluded) == 21
    with pytest.raises(DailyRefreshConflict):
        reader.request_recollection(
            run_date=date(2026, 9, 5), idempotency_key="reject-79-no-force-recollect"
        )


def test_old_claim_is_rejected_and_failed_day_rearm_preserves_limits(availability_db):
    harness, _, store, reader, _, old_claim = availability_db
    with harness.connect("admin") as admin:
        admin.execute(
            "UPDATE dev_eval.daily_glm_refresh_commands "
            "SET lease_expires_at=CURRENT_TIMESTAMP-INTERVAL '1 second' "
            "WHERE command_id=%s",
            (old_claim,),
        )
    assert store.claim_recollection() is None
    assert reader.recollection_command(command_id=str(old_claim)).status == "REJECTED"
    old_execution = reader.execution_detail(run_date=CLAIMED_DATE, execution_sequence=1).execution
    assert old_execution.authority_sha256 == DAILY_REFRESH_AUTHORITY.authority_sha256
    assert old_execution.status == "INTERRUPTED"
    original = reader.execution_detail(run_date=FAILED_DATE, execution_sequence=0).execution
    for sequence in range(1, 4):
        requested = reader.request_recollection(
            run_date=FAILED_DATE, idempotency_key=f"availability-recollect-{sequence}"
        )
        claimed = store.claim_recollection(lease_seconds=15)
        assert claimed.command_id == requested.command_id
        assert claimed.execution_sequence == sequence
        current = reader.execution_detail(
            run_date=FAILED_DATE, execution_sequence=sequence
        ).execution
        assert current.authority_sha256 == DAILY_REFRESH_AUTHORITY_V2.authority_sha256
        assert (
            reader.execution_detail(run_date=FAILED_DATE, execution_sequence=0).execution
            == original
        )
        if sequence == 1:
            with harness.connect("admin") as admin:
                admin.execute(
                    "UPDATE dev_eval.daily_glm_refresh_commands "
                    "SET lease_expires_at=CURRENT_TIMESTAMP-INTERVAL '1 second' "
                    "WHERE command_id=%s",
                    (claimed.command_id,),
                )
            recovered = store.claim_recollection()
            assert recovered.execution_sequence == 1
            assert recovered.command_id == claimed.command_id
        store.finish(
            run_date=FAILED_DATE,
            status=DailyRefreshRunStatus.COLLECTION_INCOMPLETE,
            changed_count=0,
            failed_count=0,
            safe_reason="TOUR_API_COLLECTION_FAILED",
        )
        store.complete_recollection(
            command_id=claimed.command_id, status="FAILED", safe_reason="TOUR_API_COLLECTION_FAILED"
        )
    with pytest.raises(DailyRefreshConflict):
        reader.request_recollection(
            run_date=FAILED_DATE, idempotency_key="availability-recollect-four"
        )


def test_new_policy_history_blocks_downgrade(availability_db):
    from sqlalchemy.exc import DBAPIError

    harness, _, store, reader, _, _ = availability_db
    active = reader.active_release()
    with pytest.raises(DBAPIError, match="requires an explicit data migration"):
        command.downgrade(_config(harness), "0025_daily_glm_operations")
    assert reader.active_release() == active
    assert store.baseline_snapshot() is not None


def test_retention_protects_baseline_and_referenced_scoring_snapshots(availability_db):
    _, _, store, reader, old, _ = availability_db
    active = reader.active_release()
    referenced = {active.snapshot_sha256, old["snapshot_sha256"]}
    referenced.update(e.lineage.source_snapshot_sha256 for e in active.profile_entries)
    referenced.update(
        e.baseline_observation.snapshot_sha256
        for e in active.profile_entries
        if e.baseline_observation is not None
    )
    store.purge(cutoff=date(2026, 9, 6))
    for sha in referenced:
        assert store.get_snapshot(sha) is not None
    assert reader.active_release() == active
