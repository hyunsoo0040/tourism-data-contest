from __future__ import annotations

import json
from datetime import date

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from sqlalchemy import create_engine, text

from itda.contracts.mvp_daily_refresh import (
    DAILY_REFRESH_AUTHORITY,
    DAILY_REFRESH_MEMBERSHIP_SHA256,
)
from itda.contracts.mvp_place_scoring import MVP_SCORING_PROMPT_SHA256
from itda.db.session import sqlalchemy_url_from_dsn
from tests.integration.profile_release_test_support import (
    DAILY_GLM_SERVICE_ROLE,
    DAILY_GLM_WRITE_AUTHORITY_ROLE,
    ensure_daily_glm_refresh_roles,
    ensure_photo_lifecycle_roles,
    ensure_profile_release_authority_roles,
    ensure_profile_session_roles,
)
from tests.integration.test_migrations import ALEMBIC_CONFIG

RUN_DATE = date(2026, 9, 6)
SNAPSHOT_SHA = "1" * 64
PLAN_SHA = "2" * 64
PLACE_ID = f"public:gyeongju:{'3' * 64}"
REQUEST_SHA = "4" * 64


def _config(postgres_harness: object) -> Config:
    ensure_profile_release_authority_roles(postgres_harness)  # type: ignore[arg-type]
    ensure_profile_session_roles(postgres_harness)  # type: ignore[arg-type]
    ensure_photo_lifecycle_roles(postgres_harness)  # type: ignore[arg-type]
    config = Config(str(ALEMBIC_CONFIG))
    config.set_main_option(
        "sqlalchemy.url",
        sqlalchemy_url_from_dsn(postgres_harness.dsns["admin"]).render_as_string(  # type: ignore[attr-defined]
            hide_password=False
        ),
    )
    config.attributes["runtime_role"] = postgres_harness.role_names["runtime"]  # type: ignore[attr-defined]
    config.attributes["database_name"] = postgres_harness.database_name  # type: ignore[attr-defined]
    config.attributes["profile_release_authorization_hmac_key"] = "41" * 32
    for capability in ("dev", "sealer", "evaluator"):
        config.attributes[f"{capability}_role"] = postgres_harness.role_names[  # type: ignore[attr-defined]
            capability
        ]
    config.attributes["label_builder_role"] = postgres_harness.role_names["dev"]  # type: ignore[attr-defined]
    return config


def _service_dsn(postgres_harness: object) -> str:
    fixed = ensure_daily_glm_refresh_roles(postgres_harness)  # type: ignore[arg-type]
    values = conninfo_to_dict(postgres_harness.dsns["admin"])  # type: ignore[attr-defined]
    return make_conninfo(
        **(
            values
            | {
                "user": fixed["service_role"],
                "password": fixed["service_password"],
            }
        )
    )


def _snapshot_payload() -> dict[str, object]:
    return {
        "schema_version": "mvp-daily-scoring-input-snapshot.v1",
        "run_date": RUN_DATE.isoformat(),
        "collected_at": "2026-09-06T00:00:00Z",
        "authority_sha256": DAILY_REFRESH_AUTHORITY.authority_sha256,
        "membership_sha256": DAILY_REFRESH_MEMBERSHIP_SHA256,
        "previous_snapshot_sha256": None,
        "places": [{"place_id": f"public:gyeongju:{index:064x}"} for index in range(100)],
        "snapshot_sha256": SNAPSHOT_SHA,
    }


def _plan_payload() -> dict[str, object]:
    return {
        "schema_version": "mvp-daily-incremental-scoring-plan.v1",
        "run_date": RUN_DATE.isoformat(),
        "authority_sha256": DAILY_REFRESH_AUTHORITY.authority_sha256,
        "snapshot_sha256": SNAPSHOT_SHA,
        "delta_sha256": "5" * 64,
        "endpoint": "https://api.z.ai/api/coding/paas/v4/chat/completions",
        "model": "glm-5.3-flash",
        "prompt_sha256": MVP_SCORING_PROMPT_SHA256,
        "changed_place_ids": [PLACE_ID],
        "request_sha256": [REQUEST_SHA],
        "first_pass_count": 1,
        "retry_limit_per_place": 1,
        "maximum_calls": 200,
        "concurrency": 1,
        "fallback": False,
        "pay_as_you_go_fallback": False,
        "plan_sha256": PLAN_SHA,
    }


def test_daily_glm_authority_enforces_claim_reservation_and_acl(
    postgres_harness: object,
) -> None:
    config = _config(postgres_harness)
    command.upgrade(config, "0025_daily_glm_operations")
    service_dsn = _service_dsn(postgres_harness)
    runtime_dsn = postgres_harness.dsns["runtime"]  # type: ignore[attr-defined]

    with postgres_harness.connect("admin") as admin:  # type: ignore[attr-defined]
        roles = admin.execute(
            "SELECT rolname,rolcanlogin,rolinherit,rolsuper,rolcreatedb,"
            "rolcreaterole,rolreplication,rolbypassrls FROM pg_catalog.pg_roles "
            "WHERE rolname IN (%s,%s) ORDER BY rolname",
            (DAILY_GLM_SERVICE_ROLE, DAILY_GLM_WRITE_AUTHORITY_ROLE),
        ).fetchall()
        assert roles == [
            (
                DAILY_GLM_SERVICE_ROLE,
                True,
                False,
                False,
                False,
                False,
                False,
                False,
            ),
            (
                DAILY_GLM_WRITE_AUTHORITY_ROLE,
                False,
                False,
                False,
                False,
                False,
                False,
                False,
            ),
        ]
        functions = admin.execute(
            "SELECT p.proname,p.prosecdef,p.proconfig FROM pg_catalog.pg_proc p "
            "JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace "
            "WHERE n.nspname='dev_eval' AND p.proname LIKE '%daily_glm%'"
        ).fetchall()
        assert len(functions) == 22
        assert all(row[1] and row[2] == ["search_path=pg_catalog, pg_temp"] for row in functions)

    for dsn in (service_dsn, runtime_dsn):
        with (
            psycopg.connect(dsn) as connection,
            pytest.raises(psycopg.errors.InsufficientPrivilege),
        ):
            connection.execute(
                "INSERT INTO dev_eval.daily_glm_refresh_runs "
                "(run_date,status,authority_sha256) VALUES (%s,'RUNNING',%s)",
                (RUN_DATE, DAILY_REFRESH_AUTHORITY.authority_sha256),
            )

    with psycopg.connect(service_dsn) as service:
        assert service.execute(
            "SELECT dev_eval.claim_daily_glm_refresh_v1(%s,%s)",
            (RUN_DATE, DAILY_REFRESH_AUTHORITY.authority_sha256),
        ).fetchone() == (True,)
        service.commit()
        assert service.execute(
            "SELECT dev_eval.claim_daily_glm_refresh_v1(%s,%s)",
            (RUN_DATE, DAILY_REFRESH_AUTHORITY.authority_sha256),
        ).fetchone() == (False,)
        service.commit()
        service.execute(
            "SELECT dev_eval.store_daily_glm_snapshot_v1(%s,%s,%s,%s,%s::jsonb)",
            (
                RUN_DATE,
                SNAPSHOT_SHA,
                None,
                DAILY_REFRESH_MEMBERSHIP_SHA256,
                json.dumps(_snapshot_payload()),
            ),
        )
        service.execute(
            "SELECT dev_eval.store_daily_glm_scoring_plan_v1(%s,%s,%s,%s::jsonb)",
            (RUN_DATE, PLAN_SHA, SNAPSHOT_SHA, json.dumps(_plan_payload())),
        )
        service.commit()
        assert service.execute(
            "SELECT dev_eval.reserve_daily_glm_call_v1(%s,%s,%s,%s,1)",
            (RUN_DATE, PLAN_SHA, PLACE_ID, REQUEST_SHA),
        ).fetchone() == (1,)
        service.commit()
        with pytest.raises(psycopg.errors.CheckViolation):
            service.execute(
                "SELECT dev_eval.reserve_daily_glm_call_v1(%s,%s,%s,%s,2)",
                (RUN_DATE, PLAN_SHA, PLACE_ID, REQUEST_SHA),
            )
        service.rollback()
        service.execute(
            "SELECT dev_eval.finish_daily_glm_attempt_v1(%s,%s,1,'FAILED','GLM_TIMEOUT',NULL)",
            (RUN_DATE, PLACE_ID),
        )
        service.commit()
        assert service.execute(
            "SELECT dev_eval.reserve_daily_glm_call_v1(%s,%s,%s,%s,2)",
            (RUN_DATE, PLAN_SHA, PLACE_ID, REQUEST_SHA),
        ).fetchone() == (2,)
        service.commit()

    engine = create_engine(sqlalchemy_url_from_dsn(postgres_harness.dsns["admin"]))  # type: ignore[attr-defined]
    with engine.connect() as connection:
        assert (
            connection.execute(
                text(
                    "SELECT call_count FROM dev_eval.daily_glm_refresh_runs "
                    "WHERE run_date=:run_date"
                ),
                {"run_date": RUN_DATE},
            ).scalar_one()
            == 2
        )
    engine.dispose()


def test_daily_glm_operations_recollection_is_idempotent_and_audited(
    postgres_harness: object,
) -> None:
    config = _config(postgres_harness)
    command.upgrade(config, "0025_daily_glm_operations")
    service_dsn = _service_dsn(postgres_harness)
    runtime_dsn = postgres_harness.dsns["runtime"]  # type: ignore[attr-defined]
    run_date = date(2026, 9, 7)
    idempotency_key = "daily-recollect-20260907"

    with psycopg.connect(service_dsn) as service:
        assert service.execute(
            "SELECT dev_eval.claim_daily_glm_refresh_v1(%s,%s)",
            (run_date, DAILY_REFRESH_AUTHORITY.authority_sha256),
        ).fetchone() == (True,)
        service.execute(
            "SELECT dev_eval.record_daily_glm_collection_failure_v1(%s,%s,%s,%s,%s)",
            (run_date, PLACE_ID, "detailIntro2", "PROVIDER_TRANSPORT", "PROVIDER_UNAVAILABLE"),
        )
        service.execute(
            "SELECT dev_eval.finish_daily_glm_refresh_v1(%s,%s,0,0,%s)",
            (run_date, "COLLECTION_INCOMPLETE", "TOUR_API_COLLECTION_FAILED"),
        )
        service.commit()

    with psycopg.connect(runtime_dsn) as runtime:
        overview = runtime.execute(
            "SELECT recollection_eligible,recollection_reason "
            "FROM dev_eval.read_daily_glm_operations_overview_v1()"
        ).fetchone()
        assert overview == (True, "RECOLLECTION_ALLOWED")
        command_row = runtime.execute(
            "SELECT command_id,status FROM dev_eval.request_daily_glm_recollection_v1(%s,%s)",
            (run_date, idempotency_key),
        ).fetchone()
        runtime.commit()
        replay = runtime.execute(
            "SELECT command_id,status FROM dev_eval.request_daily_glm_recollection_v1(%s,%s)",
            (run_date, idempotency_key),
        ).fetchone()
        assert replay == command_row
        runtime.commit()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            runtime.execute(
                "INSERT INTO dev_eval.daily_glm_refresh_commands(run_date,idempotency_key,status) "
                "VALUES (%s,%s,'REQUESTED')",
                (run_date, "another-valid-key-20260907"),
            )
        runtime.rollback()

    with psycopg.connect(service_dsn) as service:
        claimed = service.execute(
            "SELECT command_id,status,execution_sequence "
            "FROM dev_eval.claim_daily_glm_recollection_v1(60)"
        ).fetchone()
        assert claimed == (command_row[0], "CLAIMED", 1)
        assert service.execute(
            "SELECT count(*) FROM dev_eval.claim_daily_glm_recollection_v1(60)"
        ).fetchone() == (0,)
        failures = service.execute(
            "SELECT execution_sequence,operation,failure_category,failure_code "
            "FROM dev_eval.read_daily_glm_collection_failures_v1(%s,0)",
            (run_date,),
        ).fetchall()
        assert failures == [(0, "detailIntro2", "PROVIDER_TRANSPORT", "PROVIDER_UNAVAILABLE")]
        service.execute(
            "SELECT dev_eval.finish_daily_glm_refresh_v1(%s,%s,0,0,%s)",
            (run_date, "COLLECTION_INCOMPLETE", "TOUR_API_COLLECTION_FAILED"),
        )
        service.execute(
            "SELECT dev_eval.complete_daily_glm_recollection_v1(%s,%s,%s)",
            (command_row[0], "FAILED", "TOUR_API_COLLECTION_FAILED"),
        )
        service.commit()
        executions = service.execute(
            "SELECT execution_sequence,kind,status FROM "
            "dev_eval.read_daily_glm_execution_history_v1(30) WHERE run_date=%s",
            (run_date,),
        ).fetchall()
        assert executions == [
            (1, "MANUAL_RECOLLECTION", "COLLECTION_INCOMPLETE"),
            (0, "SCHEDULED", "COLLECTION_INCOMPLETE"),
        ]

    with postgres_harness.connect("admin") as admin:  # type: ignore[attr-defined]
        events = admin.execute(
            "SELECT status FROM dev_eval.daily_glm_refresh_command_events "
            "WHERE command_id=%s ORDER BY event_seq",
            (command_row[0],),
        ).fetchall()
        assert events == [("REQUESTED",), ("CLAIMED",), ("FAILED",)]


def test_daily_glm_recollection_limit_and_expired_lease_recovery(
    postgres_harness: object,
) -> None:
    config = _config(postgres_harness)
    command.upgrade(config, "0025_daily_glm_operations")
    service_dsn = _service_dsn(postgres_harness)
    runtime_dsn = postgres_harness.dsns["runtime"]  # type: ignore[attr-defined]
    run_date = date(2026, 9, 8)

    with psycopg.connect(service_dsn) as service:
        assert service.execute(
            "SELECT dev_eval.claim_daily_glm_refresh_v1(%s,%s)",
            (run_date, DAILY_REFRESH_AUTHORITY.authority_sha256),
        ).fetchone() == (True,)
        service.execute(
            "SELECT dev_eval.finish_daily_glm_refresh_v1(%s,%s,0,0,%s)",
            (run_date, "COLLECTION_INCOMPLETE", "TOUR_API_COLLECTION_FAILED"),
        )
        service.commit()

    first_command_id = None
    for sequence in range(1, 4):
        with psycopg.connect(runtime_dsn) as runtime:
            requested = runtime.execute(
                "SELECT command_id FROM dev_eval.request_daily_glm_recollection_v1(%s,%s)",
                (run_date, f"daily-recollect-20260908-{sequence}"),
            ).fetchone()
            runtime.commit()
        with psycopg.connect(service_dsn) as service:
            claimed = service.execute(
                "SELECT command_id,execution_sequence FROM "
                "dev_eval.claim_daily_glm_recollection_v1(60)"
            ).fetchone()
            assert claimed == (requested[0], sequence)
            if sequence == 1:
                first_command_id = requested[0]
                service.commit()
                with postgres_harness.connect("admin") as admin:  # type: ignore[attr-defined]
                    admin.execute(
                        "UPDATE dev_eval.daily_glm_refresh_commands "
                        "SET lease_expires_at=CURRENT_TIMESTAMP-INTERVAL '1 second' "
                        "WHERE command_id=%s",
                        (requested[0],),
                    )
                reclaimed = service.execute(
                    "SELECT command_id,execution_sequence FROM "
                    "dev_eval.claim_daily_glm_recollection_v1(60)"
                ).fetchone()
                assert reclaimed == claimed
            service.execute(
                "SELECT dev_eval.finish_daily_glm_refresh_v1(%s,%s,0,0,%s)",
                (run_date, "COLLECTION_INCOMPLETE", "TOUR_API_COLLECTION_FAILED"),
            )
            service.execute(
                "SELECT dev_eval.complete_daily_glm_recollection_v1(%s,%s,%s)",
                (requested[0], "FAILED", "TOUR_API_COLLECTION_FAILED"),
            )
            service.commit()

    with psycopg.connect(runtime_dsn) as runtime:
        overview = runtime.execute(
            "SELECT recollection_eligible,recollection_reason FROM "
            "dev_eval.read_daily_glm_operations_overview_v1()"
        ).fetchone()
        assert overview == (False, "MANUAL_RECOLLECTION_LIMIT_REACHED")
        with pytest.raises(psycopg.errors.CheckViolation):
            runtime.execute(
                "SELECT * FROM dev_eval.request_daily_glm_recollection_v1(%s,%s)",
                (run_date, "daily-recollect-20260908-4"),
            )
        runtime.rollback()

    with postgres_harness.connect("admin") as admin:  # type: ignore[attr-defined]
        assert admin.execute(
            "SELECT count(*) FROM dev_eval.daily_glm_refresh_command_events "
            "WHERE command_id=%s AND status='CLAIMED'",
            (first_command_id,),
        ).fetchone() == (2,)


def test_daily_glm_operations_migration_round_trip(postgres_harness: object) -> None:
    config = _config(postgres_harness)
    command.upgrade(config, "0025_daily_glm_operations")
    command.downgrade(config, "0024_daily_glm_refresh")
    with postgres_harness.connect("admin") as admin:  # type: ignore[attr-defined]
        assert admin.execute(
            "SELECT to_regclass('dev_eval.daily_glm_refresh_executions')"
        ).fetchone() == (None,)
        assert admin.execute(
            "SELECT count(*) FROM pg_catalog.pg_proc p "
            "JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace "
            "WHERE n.nspname='dev_eval' AND p.proname LIKE '%daily_glm%'"
        ).fetchone() == (10,)
    command.upgrade(config, "0025_daily_glm_operations")
