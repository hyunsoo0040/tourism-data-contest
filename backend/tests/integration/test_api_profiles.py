from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError

from itda.api.dependencies import (
    PROFILE_SESSION_COOKIE_NAME,
    get_preference_service,
    reset_profile_session_caches,
)
from itda.api.main import app
from itda.application.preferences import PreferenceService
from itda.contracts.base import ExperienceAxis
from itda.contracts.preference import (
    AxisScore,
    PreferenceProfile,
    QuestionnaireAnswersV1,
    QuestionnaireSubmission,
    TripConditions,
)
from itda.db.repositories import ProfileRepository
from itda.db.session import create_database_engine, create_session_factory, sqlalchemy_url_from_dsn
from itda.domain.preference import calculate_preference
from tests.integration.profile_release_test_support import (
    ensure_photo_lifecycle_roles,
    ensure_profile_release_authority_roles,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ALEMBIC_CONFIG = REPOSITORY_ROOT / "backend" / "alembic.ini"
QUESTIONNAIRE_ARTIFACT = REPOSITORY_ROOT / "contracts" / "questionnaire-v2.json"
CREATED_AT = datetime(2026, 7, 22, 13, 0, tzinfo=UTC)
ORIGIN = "https://testserver"
SESSION_OWNER = "itda_current_profile_session_owner"
SESSION_SERVICE = "itda_current_profile_session_service"


def _submission_payload(request_id: str = "anonymous:request:api-profile") -> dict[str, object]:
    return {
        "request_id": request_id,
        "trip_conditions": {
            "visit_date": "2026-10-09",
            "visit_time": "SUNSET",
            "companion": "FRIEND_OR_PARTNER",
            "transport": "MIXED",
            "walking_tolerance": "ABOUT_1_HOUR",
            "indoor_outdoor_preference": "NO_PREFERENCE",
            "crowd_avoidance": "HIGH",
        },
        "answers": {
            "q1": 3,
            "q2": 2,
            "q3": 3,
            "q4": 2,
            "q5": 3,
            "q6": 2,
            "q7": 3,
            "q8": 2,
            "q9": 1,
            "q10": 2,
            "q11": 3,
            "q12": 1,
        },
    }


def _provision_roles(postgres_harness: object, service_password: str) -> None:
    ensure_profile_release_authority_roles(postgres_harness)
    ensure_photo_lifecycle_roles(postgres_harness)
    with postgres_harness.connect("admin", autocommit=True) as connection:
        for role, login in ((SESSION_OWNER, False), (SESSION_SERVICE, True)):
            exists = connection.execute(
                "SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = %s", (role,)
            ).fetchone()
            if exists is None:
                statement = (
                    "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOREPLICATION NOBYPASSRLS NOINHERIT"
                    if login
                    else "CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOREPLICATION NOBYPASSRLS NOINHERIT"
                )
                params = [sql.Identifier(role)]
                if login:
                    params.append(sql.Literal(service_password))
                connection.execute(sql.SQL(statement).format(*params))
            elif login:
                connection.execute(
                    sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                        sql.Identifier(role), sql.Literal(service_password)
                    )
                )
        connection.execute(
            sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                sql.Identifier(postgres_harness.database_name), sql.Identifier(SESSION_SERVICE)
            )
        )


def _session_service_dsn(postgres_harness: object, password: str) -> str:
    info = conninfo_to_dict(postgres_harness.dsns["admin"])
    return make_conninfo(**(info | {"user": SESSION_SERVICE, "password": password}))


def _migration_config(postgres_harness: object) -> Config:
    config = Config(str(ALEMBIC_CONFIG))
    config.set_main_option(
        "sqlalchemy.url",
        sqlalchemy_url_from_dsn(postgres_harness.dsns["admin"]).render_as_string(
            hide_password=False
        ),
    )
    config.attributes["runtime_role"] = postgres_harness.role_names["runtime"]
    config.attributes["database_name"] = postgres_harness.database_name
    config.attributes["label_builder_role"] = postgres_harness.role_names["dev"]
    config.attributes["profile_release_authorization_hmac_key"] = "41" * 32
    return config


def _migrate(postgres_harness: object, service_password: str) -> None:
    _provision_roles(postgres_harness, service_password)
    command.upgrade(_migration_config(postgres_harness), "head")


def _session_environment(monkeypatch: pytest.MonkeyPatch, dsn: str, session_dsn: str) -> None:
    current = base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
    previous = base64.urlsafe_b64encode(b"p" * 32).decode().rstrip("=")
    monkeypatch.setenv("ITDA_DATABASE_URL", dsn)
    monkeypatch.setenv("ITDA_PROFILE_SESSION_DATABASE_URL", session_dsn)
    monkeypatch.setenv("ITDA_PROFILE_SESSION_KEYRING", f"current.{current},previous.{previous}")
    monkeypatch.setenv("ITDA_PROFILE_SESSION_CURRENT_KID", "current")
    monkeypatch.setenv("ITDA_CANONICAL_APP_ORIGIN", ORIGIN)
    monkeypatch.delenv("ITDA_E2E_ALLOW_INSECURE_COOKIE", raising=False)
    monkeypatch.setenv("ITDA_API_BIND_HOST", "127.0.0.1")
    reset_profile_session_caches()


@pytest.fixture
def api_client(postgres_harness: object, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    service_password = secrets.token_urlsafe(24)
    _migrate(postgres_harness, service_password)
    admin_engine = create_engine(sqlalchemy_url_from_dsn(postgres_harness.dsns["admin"]))
    with admin_engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE app.current_profile_sessions, app.preference_profiles, "
                "app.journey_drafts CASCADE"
            )
        )
    admin_engine.dispose()

    runtime_engine: Engine = create_database_engine(postgres_harness.dsns["runtime"])
    repository = ProfileRepository(create_session_factory(runtime_engine))
    service = PreferenceService(repository, clock=lambda: CREATED_AT)
    app.dependency_overrides[get_preference_service] = lambda: service
    _session_environment(
        monkeypatch,
        postgres_harness.dsns["runtime"],
        _session_service_dsn(postgres_harness, service_password),
    )
    try:
        with TestClient(app, base_url=ORIGIN, headers={"Origin": ORIGIN}) as client:
            yield client
    finally:
        app.dependency_overrides.clear()
        reset_profile_session_caches()
        runtime_engine.dispose()


@pytest.mark.parametrize("default_owner", ["creator", "session_owner"])
@pytest.mark.parametrize("object_kind", ["TABLES", "SEQUENCES", "FUNCTIONS"])
def test_migration_rejects_unrelated_default_privileges(
    postgres_harness: object,
    default_owner: str,
    object_kind: str,
) -> None:
    service_password = secrets.token_urlsafe(24)
    _provision_roles(postgres_harness, service_password)
    config = _migration_config(postgres_harness)
    command.upgrade(config, "0018_phase6_photo_jobs_and_deletion_ledger")
    unrelated = postgres_harness.role_names["dev"]
    subject = (
        postgres_harness.role_names["admin"]
        if default_owner == "creator"
        else SESSION_OWNER
    )
    privilege = "EXECUTE" if object_kind == "FUNCTIONS" else "ALL"
    with postgres_harness.connect("admin", autocommit=True) as connection:
        connection.execute(
            sql.SQL("ALTER DEFAULT PRIVILEGES FOR ROLE {} GRANT {} ON {} TO {}").format(
                sql.Identifier(subject),
                sql.SQL(privilege),
                sql.SQL(object_kind),
                sql.Identifier(unrelated),
            )
        )
    try:
        with pytest.raises(RuntimeError, match="default privileges rejected"):
            command.upgrade(config, "head")
        with postgres_harness.connect("admin") as connection:
            revision = connection.execute(
                "SELECT version_num FROM alembic_version"
            ).fetchone()[0]
            session_objects = connection.execute(
                "SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n "
                "ON n.oid=c.relnamespace WHERE n.nspname='app' "
                "AND c.relname='current_profile_sessions'"
            ).fetchone()[0]
        assert revision == "0018_phase6_photo_jobs_and_deletion_ledger"
        assert session_objects == 0
    finally:
        with postgres_harness.connect("admin", autocommit=True) as connection:
            connection.execute(
                sql.SQL(
                    "ALTER DEFAULT PRIVILEGES FOR ROLE {} REVOKE {} ON {} FROM {}"
                ).format(
                    sql.Identifier(subject),
                    sql.SQL(privilege),
                    sql.SQL(object_kind),
                    sql.Identifier(unrelated),
                )
            )
    command.upgrade(config, "head")
    command.downgrade(config, "0018_phase6_photo_jobs_and_deletion_ledger")


def test_current_questionnaire_equals_committed_canonical_artifact(api_client: TestClient) -> None:
    response = api_client.get("/v1/questionnaires/current")
    assert response.status_code == 200
    assert response.json() == json.loads(QUESTIONNAIRE_ARTIFACT.read_text())


def test_profile_create_sets_digest_backed_host_only_cookie_and_get_requires_it(
    api_client: TestClient, postgres_harness: object
) -> None:
    payload = _submission_payload()
    expected = calculate_preference(
        QuestionnaireSubmission.model_validate(payload), created_at=CREATED_AT
    ).model_dump(mode="json")

    created = api_client.post("/v1/preference-profiles", json=payload)
    assert created.status_code == 201
    assert created.json() == expected
    cookie_header = created.headers["set-cookie"]
    assert f"{PROFILE_SESSION_COOKIE_NAME}=" in cookie_header
    assert "HttpOnly" in cookie_header
    assert "Secure" in cookie_header
    assert "SameSite=strict" in cookie_header
    assert "Path=/" in cookie_header
    assert "Domain=" not in cookie_header
    assert "Max-Age=1800" in cookie_header
    cookie_value = api_client.cookies.get(PROFILE_SESSION_COOKIE_NAME)
    assert cookie_value is not None
    assert expected["profile_id"] not in cookie_value
    assert str(payload["request_id"]) not in cookie_value
    assert "answers" not in cookie_value
    assert len(cookie_value) <= 160

    raw_reference = cookie_value.split(".")[2]
    digest = hashlib.sha256(raw_reference.encode()).hexdigest()
    with postgres_harness.connect("admin") as connection:
        rows = connection.execute(
            "SELECT session_digest, profile_id, expires_at - issued_at, revoked_at "
            "FROM app.current_profile_sessions"
        ).fetchall()
    assert len(rows) == 1
    assert rows[0][0] == digest
    assert rows[0][1] == expected["profile_id"]
    assert rows[0][2].total_seconds() == 1800
    assert rows[0][3] is None
    assert raw_reference not in repr(rows)

    recovered = api_client.get(f"/v1/preference-profiles/{expected['profile_id']}")
    assert recovered.status_code == 200
    assert recovered.json() == expected

    api_client.cookies.clear()
    denied = api_client.get(f"/v1/preference-profiles/{expected['profile_id']}")
    assert denied.status_code == 401


def test_identifier_only_replay_and_foreign_get_never_reissue_authority(
    api_client: TestClient,
) -> None:
    first_payload = _submission_payload("anonymous:request:closed-replay")
    first = api_client.post("/v1/preference-profiles", json=first_payload)
    assert first.status_code == 201
    profile_id = first.json()["profile_id"]
    valid_cookie = api_client.cookies.get(PROFILE_SESSION_COOKIE_NAME)

    api_client.cookies.clear()
    replay = api_client.post("/v1/preference-profiles", json=first_payload)
    assert replay.status_code == 409
    assert "set-cookie" not in replay.headers

    foreign = api_client.get(f"/v1/preference-profiles/{profile_id}")
    assert foreign.status_code == 401
    assert "set-cookie" not in foreign.headers

    api_client.cookies.set(PROFILE_SESSION_COOKIE_NAME, valid_cookie)
    matching_replay = api_client.post("/v1/preference-profiles", json=first_payload)
    assert matching_replay.status_code == 201
    assert "set-cookie" in matching_replay.headers


def test_replacement_revokes_predecessor_and_tampering_is_denied(api_client: TestClient) -> None:
    first = api_client.post(
        "/v1/preference-profiles",
        json=_submission_payload("anonymous:request:replacement-one"),
    )
    assert first.status_code == 201
    predecessor = api_client.cookies.get(PROFILE_SESSION_COOKIE_NAME)

    second = api_client.post(
        "/v1/preference-profiles",
        json=_submission_payload("anonymous:request:replacement-two"),
    )
    assert second.status_code == 201
    successor = api_client.cookies.get(PROFILE_SESSION_COOKIE_NAME)
    assert successor != predecessor

    api_client.cookies.set(PROFILE_SESSION_COOKIE_NAME, predecessor)
    assert (
        api_client.get(f"/v1/preference-profiles/{first.json()['profile_id']}").status_code == 401
    )
    api_client.cookies.set(PROFILE_SESSION_COOKIE_NAME, successor[:-1] + "x")
    assert (
        api_client.get(f"/v1/preference-profiles/{second.json()['profile_id']}").status_code == 401
    )


def test_expired_and_revoked_sessions_are_denied(
    api_client: TestClient, postgres_harness: object
) -> None:
    created = api_client.post(
        "/v1/preference-profiles", json=_submission_payload("anonymous:request:expiry")
    )
    profile_id = created.json()["profile_id"]
    cookie_value = api_client.cookies.get(PROFILE_SESSION_COOKIE_NAME)
    assert cookie_value is not None
    digest = hashlib.sha256(cookie_value.split(".")[2].encode()).hexdigest()

    with postgres_harness.connect("admin", autocommit=True) as connection:
        connection.execute(
            "UPDATE app.current_profile_sessions "
            "SET issued_at = CURRENT_TIMESTAMP - interval '31 minutes', "
            "expires_at = CURRENT_TIMESTAMP - interval '1 minute' "
            "WHERE session_digest = %s",
            (digest,),
        )
    assert api_client.get(f"/v1/preference-profiles/{profile_id}").status_code == 401


def test_session_objects_have_function_only_least_privilege(
    api_client: TestClient, postgres_harness: object
) -> None:
    del api_client
    runtime = postgres_harness.role_names["runtime"]
    with postgres_harness.connect("admin") as connection:
        owner = connection.execute(
            "SELECT rolcanlogin, rolinherit, rolsuper, rolcreatedb, rolcreaterole, "
            "rolreplication, rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = %s",
            (SESSION_OWNER,),
        ).fetchone()
        assert owner == (False, False, False, False, False, False, False)
        memberships = connection.execute(
            "SELECT pg_has_role(%s,%s,'MEMBER'), pg_has_role(%s,%s,'MEMBER'), "
            "pg_has_role(%s,%s,'MEMBER'), pg_has_role(%s,%s,'MEMBER'), "
            "pg_has_role(%s,%s,'MEMBER'), pg_has_role(%s,%s,'MEMBER')",
            (
                runtime, SESSION_OWNER, runtime, SESSION_SERVICE,
                SESSION_OWNER, runtime, SESSION_OWNER, SESSION_SERVICE,
                SESSION_SERVICE, runtime, SESSION_SERVICE, SESSION_OWNER,
            ),
        ).fetchone()
        assert memberships == (False, False, False, False, False, False)
        direct = connection.execute(
            "SELECT has_table_privilege(%s, 'app.current_profile_sessions', 'SELECT'), "
            "has_table_privilege(%s, 'app.current_profile_sessions', "
            "'INSERT,UPDATE,DELETE,TRUNCATE'), "
            "has_schema_privilege(%s, 'app', 'CREATE'), "
            "has_table_privilege('public', 'app.current_profile_sessions', 'SELECT'), "
            "has_schema_privilege('public', 'app', 'CREATE')",
            (runtime, runtime, runtime),
        ).fetchone()
        assert direct == (False, False, False, False, False)
        functions = connection.execute(
            "SELECT proname, prosecdef, proconfig FROM pg_catalog.pg_proc p "
            "JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace "
            "WHERE n.nspname='app' AND (proname LIKE '%current_profile_session%' OR "
            "proname='create_preference_profile_and_issue_session_v1') ORDER BY proname"
        ).fetchall()
        assert {row[0] for row in functions} == {
            "create_preference_profile_and_issue_session_v1",
            "issue_current_profile_session_v1",
            "purge_current_profile_sessions_v1",
            "resolve_current_profile_session_v1",
            "revoke_current_profile_session_v1",
            "rotate_current_profile_session_v1",
        }
        assert all(
            row[1] is True and row[2] == ["search_path=pg_catalog, pg_temp"] for row in functions
        )
        function_acl = connection.execute(
            "SELECT p.proname, grantee.rolname, a.privilege_type, a.is_grantable "
            "FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n "
            "ON n.oid=p.pronamespace CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a "
            "JOIN pg_catalog.pg_roles grantee ON grantee.oid=a.grantee "
            "WHERE n.nspname='app' AND (p.proname LIKE '%current_profile_session%' OR "
            "p.proname='create_preference_profile_and_issue_session_v1') ORDER BY p.proname"
        ).fetchall()
        assert len(function_acl) == len(functions)
        assert all(
            grantee == SESSION_SERVICE
            and privilege == "EXECUTE"
            and is_grantable is False
            for _, grantee, privilege, is_grantable in function_acl
        )

    runtime_engine = create_engine(sqlalchemy_url_from_dsn(postgres_harness.dsns["runtime"]))
    try:
        with pytest.raises(ProgrammingError), runtime_engine.begin() as connection:
            connection.execute(text("SELECT session_digest FROM app.current_profile_sessions"))
    finally:
        runtime_engine.dispose()


def test_issue_purge_is_lock_safe_and_hard_bounded(
    api_client: TestClient,
    postgres_harness: object,
) -> None:
    live = api_client.post(
        "/v1/preference-profiles",
        json=_submission_payload("anonymous:request:bounded-live"),
    )
    assert live.status_code == 201
    live_cookie = api_client.cookies.get(PROFILE_SESSION_COOKIE_NAME)
    assert live_cookie is not None
    live_digest = hashlib.sha256(live_cookie.split(".")[2].encode()).hexdigest()
    live_profile = live.json()["profile_id"]
    new_profile = "profile:" + "a" * 64
    held_digest = "0" * 64
    peer_digest = "1" * 64
    origin_digest = "2" * 64

    with postgres_harness.connect("admin", autocommit=True) as connection:
        connection.execute(
            "INSERT INTO app.preference_profiles SELECT %s, 'anonymous:request:bounded-new', "
            "trip_conditions,answers,history_basis_points,history_display_score,"
            "emotion_basis_points,emotion_display_score,rest_basis_points,rest_display_score,"
            "description_ko,schema_version,questionnaire_version,scoring_version,"
            "description_template_version,config_hash,created_at,is_current_trip_expectation "
            "FROM app.preference_profiles WHERE profile_id=%s",
            (new_profile, live_profile),
        )
        connection.execute(
            "INSERT INTO app.current_profile_sessions("
            "session_digest,profile_id,issued_at,expires_at,revoked_at,peer_digest,origin_digest) "
            "SELECT CASE WHEN i=0 THEN %s ELSE lpad(to_hex(i),64,'0') END, %s, "
            "CURRENT_TIMESTAMP - interval '4 days' + i * interval '1 microsecond', "
            "CURRENT_TIMESTAMP - interval '4 days' + i * interval '1 microsecond' "
            "+ interval '30 minutes', "
            "CURRENT_TIMESTAMP - interval '3 days', %s, %s FROM generate_series(0,9999) i",
            (held_digest, new_profile, peer_digest, origin_digest),
        )

    configured_dsn = os.environ["ITDA_PROFILE_SESSION_DATABASE_URL"]
    bounded_dsn = make_conninfo(
        **(
            conninfo_to_dict(configured_dsn)
            | {"options": "-c lock_timeout=500 -c statement_timeout=5000"}
        )
    )
    new_digest = "f" * 64
    with postgres_harness.connect("admin") as locker:
        locker.execute(
            "SELECT 1 FROM app.current_profile_sessions WHERE session_digest=%s FOR UPDATE",
            (held_digest,),
        )
        with psycopg.connect(bounded_dsn, autocommit=True) as service:
            service.execute(
                "SELECT app.issue_current_profile_session_v1("
                "%s,%s,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP + interval '30 minutes',%s,%s,NULL)",
                (new_digest, new_profile, peer_digest, origin_digest),
            )

    with postgres_harness.connect("admin") as connection:
        stale_count = connection.execute(
            "SELECT count(*) FROM app.current_profile_sessions "
            "WHERE expires_at < CURRENT_TIMESTAMP - interval '1 day'"
        ).fetchone()[0]
        held_exists = connection.execute(
            "SELECT count(*) FROM app.current_profile_sessions WHERE session_digest=%s",
            (held_digest,),
        ).fetchone()[0]
    assert stale_count == 9744
    assert held_exists == 1
    with psycopg.connect(configured_dsn) as service:
        assert service.execute(
            "SELECT app.resolve_current_profile_session_v1(%s)", (live_digest,)
        ).fetchone()[0] == live_profile
        assert service.execute(
            "SELECT app.resolve_current_profile_session_v1(%s)", (new_digest,)
        ).fetchone()[0] == new_profile


def test_session_capacity_rejects_direct_and_atomic_issue_without_partial_state(
    api_client: TestClient,
    postgres_harness: object,
) -> None:
    predecessor = api_client.post(
        "/v1/preference-profiles",
        json=_submission_payload("anonymous:request:capacity-predecessor"),
    )
    assert predecessor.status_code == 201
    predecessor_profile = predecessor.json()["profile_id"]
    predecessor_cookie = api_client.cookies.get(PROFILE_SESSION_COOKIE_NAME)
    assert predecessor_cookie is not None
    predecessor_digest = hashlib.sha256(predecessor_cookie.split(".")[2].encode()).hexdigest()
    filler_profile = "profile:" + "b" * 64
    peer_digest = "3" * 64
    origin_digest = "4" * 64

    with postgres_harness.connect("admin", autocommit=True) as connection:
        connection.execute(
            "INSERT INTO app.preference_profiles SELECT %s, 'anonymous:request:capacity-filler', "
            "trip_conditions,answers,history_basis_points,history_display_score,"
            "emotion_basis_points,emotion_display_score,rest_basis_points,rest_display_score,"
            "description_ko,schema_version,questionnaire_version,scoring_version,"
            "description_template_version,config_hash,created_at,is_current_trip_expectation "
            "FROM app.preference_profiles WHERE profile_id=%s",
            (filler_profile, predecessor_profile),
        )
        connection.execute(
            "INSERT INTO app.current_profile_sessions("
            "session_digest,profile_id,issued_at,expires_at,revoked_at,peer_digest,origin_digest) "
            "SELECT 'e' || lpad(to_hex(i),63,'0'), %s, CURRENT_TIMESTAMP, "
            "CURRENT_TIMESTAMP + interval '30 minutes', CURRENT_TIMESTAMP, %s, %s "
            "FROM generate_series(1,9999) i",
            (filler_profile, peer_digest, origin_digest),
        )

    service_dsn = os.environ["ITDA_PROFILE_SESSION_DATABASE_URL"]
    with psycopg.connect(service_dsn, autocommit=True) as service:
        with pytest.raises(psycopg.errors.ProgramLimitExceeded) as direct:
            service.execute(
                "SELECT app.issue_current_profile_session_v1("
                "%s,%s,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP + interval '30 minutes',%s,%s,NULL)",
                ("d" * 64, filler_profile, peer_digest, origin_digest),
            )
        assert direct.value.sqlstate == "54000"

    api_client.cookies.clear()
    atomic_request = "anonymous:request:capacity-atomic"
    with pytest.raises(OperationalError) as atomic:
        api_client.post(
            "/v1/preference-profiles",
            json=_submission_payload(atomic_request),
        )
    assert atomic.value.orig.sqlstate == "54000"

    with postgres_harness.connect("admin") as connection:
        count = connection.execute(
            "SELECT count(*) FROM app.current_profile_sessions"
        ).fetchone()[0]
        new_session = connection.execute(
            "SELECT count(*) FROM app.current_profile_sessions WHERE session_digest=%s",
            ("d" * 64,),
        ).fetchone()[0]
        new_profile = connection.execute(
            "SELECT count(*) FROM app.preference_profiles WHERE request_id=%s",
            (atomic_request,),
        ).fetchone()[0]
        predecessor_state = connection.execute(
            "SELECT revoked_at FROM app.current_profile_sessions WHERE session_digest=%s",
            (predecessor_digest,),
        ).fetchone()
    assert count == 10_000
    assert new_session == 0
    assert new_profile == 0
    assert predecessor_state == (None,)


def test_profile_create_rate_and_storage_bounds_use_actual_peer_not_forwarded(
    api_client: TestClient,
) -> None:
    headers = {"X-Forwarded-For": "203.0.113.99", "Forwarded": "for=203.0.113.99"}
    statuses = [
        api_client.post(
            "/v1/preference-profiles",
            json=_submission_payload(f"anonymous:request:rate-{index}"),
            headers=headers,
        ).status_code
        for index in range(9)
    ]
    assert statuses.count(201) <= 8
    assert statuses[-1] == 429


def test_concurrent_creates_keep_bounded_single_active_session(api_client: TestClient) -> None:
    def create(index: int) -> int:
        return api_client.post(
            "/v1/preference-profiles",
            json=_submission_payload(f"anonymous:request:concurrent-{index}"),
        ).status_code

    with ThreadPoolExecutor(max_workers=8) as executor:
        statuses = list(executor.map(create, range(8)))
    assert set(statuses) <= {201, 429, 503}


def test_keyring_failures_collapse_without_secret_metadata(
    postgres_harness: object,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret_markers = ["ITDA_PROFILE_SESSION_KEYRING", "current", "previous", "tiny", "3"]
    cases = [None, "", "current.tiny", "bad-format", "current.%%%"]
    for value in cases:
        monkeypatch.setenv("ITDA_DATABASE_URL", postgres_harness.dsns["runtime"])
        monkeypatch.setenv("ITDA_CANONICAL_APP_ORIGIN", ORIGIN)
        monkeypatch.setenv("ITDA_PROFILE_SESSION_CURRENT_KID", "current")
        if value is None:
            monkeypatch.delenv("ITDA_PROFILE_SESSION_KEYRING", raising=False)
        else:
            monkeypatch.setenv("ITDA_PROFILE_SESSION_KEYRING", value)
        reset_profile_session_caches()
        with pytest.raises(RuntimeError) as captured, TestClient(app, base_url=ORIGIN):
            pass
        assert str(captured.value) == "profile session configuration rejected"
        combined = (
            str(captured.value) + capsys.readouterr().out + capsys.readouterr().err + caplog.text
        )
        assert all(marker not in combined for marker in secret_markers)


def test_atomic_issue_failure_rolls_back_profile_and_preserves_predecessor(
    api_client: TestClient,
    postgres_harness: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = api_client.post(
        "/v1/preference-profiles",
        json=_submission_payload("anonymous:request:atomic-predecessor"),
    )
    assert first.status_code == 201
    predecessor_cookie = api_client.cookies.get(PROFILE_SESSION_COOKIE_NAME)
    assert predecessor_cookie is not None
    predecessor_digest = hashlib.sha256(predecessor_cookie.split(".")[2].encode()).hexdigest()

    colliding_reference = base64.urlsafe_b64encode(b"z" * 32).decode().rstrip("=")
    colliding_digest = hashlib.sha256(colliding_reference.encode()).hexdigest()
    with postgres_harness.connect("admin", autocommit=True) as connection:
        connection.execute(
            "UPDATE app.current_profile_sessions SET session_digest=%s WHERE session_digest=%s",
            (colliding_digest, predecessor_digest),
        )
    monkeypatch.setattr(secrets, "token_bytes", lambda size: b"z" * size)

    failed_payload = _submission_payload("anonymous:request:atomic-rollback")
    with pytest.raises(IntegrityError):
        api_client.post("/v1/preference-profiles", json=failed_payload)

    with postgres_harness.connect("admin") as connection:
        profile_count = connection.execute(
            "SELECT count(*) FROM app.preference_profiles WHERE request_id=%s",
            (failed_payload["request_id"],),
        ).fetchone()[0]
        predecessor = connection.execute(
            "SELECT revoked_at FROM app.current_profile_sessions WHERE session_digest=%s",
            (colliding_digest,),
        ).fetchone()
    assert profile_count == 0
    assert predecessor == (None,)


def test_reused_request_id_with_different_input_returns_typed_conflict(
    api_client: TestClient,
) -> None:
    first_payload = _submission_payload("anonymous:request:conflicting-retry")
    different_payload = _submission_payload("anonymous:request:conflicting-retry")
    different_payload["answers"] = {**different_payload["answers"], "q9": 3}
    assert api_client.post("/v1/preference-profiles", json=first_payload).status_code == 201
    conflict = api_client.post("/v1/preference-profiles", json=different_payload)
    assert conflict.status_code == 409


def test_profile_creation_rejects_invalid_questionnaire_input(api_client: TestClient) -> None:
    payload = _submission_payload("anonymous:request:invalid")
    payload["answers"] = {**payload["answers"], "q3": "3"}
    assert api_client.post("/v1/preference-profiles", json=payload).status_code == 422


def test_stored_legacy_v1_profile_is_served_not_discarded(
    api_client: TestClient,
    postgres_harness: object,
) -> None:
    """A persisted questionnaire-v1 profile reads back through the API alongside v2.

    The repository decoder is version-discriminated: legacy v1 rows keep their
    exact stored answers/versions/hash and are never treated as corrupt.
    """

    legacy_profile = PreferenceProfile(
        profile_id="profile:legacy:v1-served",
        request_id="anonymous:request:legacy-v1-served",
        trip_conditions=TripConditions.model_validate(
            {
                "visit_date": None,
                "visit_time": "UNDECIDED",
                "companion": "SOLO",
                "transport": "WALK_OR_TRANSIT",
                "walking_tolerance": "ABOUT_1_HOUR",
                "indoor_outdoor_preference": "NO_PREFERENCE",
                "crowd_avoidance": "MEDIUM",
            }
        ),
        answers=QuestionnaireAnswersV1.model_validate(
            {f"q{number}": 3 for number in range(1, 10)}
        ),
        scores=tuple(
            AxisScore(axis=axis, basis_points=5_000, display_score=50)
            for axis in ExperienceAxis
        ),
        description_ko="legacy stored profile evidence",
        schema_version="preference-profile-v1",
        questionnaire_version="questionnaire-v1",
        scoring_version="integer-bp-v1",
        description_template_version="current-trip-expectation-v1",
        config_hash="bc24c1ca59272397bf0dad41be34cf536b6cb6215d3148567d09fbebd749b09c",
        created_at=CREATED_AT,
    )
    runtime_engine: Engine = create_database_engine(postgres_harness.dsns["runtime"])
    try:
        ProfileRepository(create_session_factory(runtime_engine)).create(legacy_profile)

        stored = api_client.app.dependency_overrides[get_preference_service]
        service = stored()  # type: ignore[operator]
        served = service.get_profile(legacy_profile.profile_id)
        assert served == legacy_profile

        current = api_client.get("/v1/questionnaires/current")
        assert current.status_code == 200
        assert current.json()["questionnaire_version"] == "questionnaire-v2"
    finally:
        runtime_engine.dispose()


def test_current_v2_profile_carries_bumped_schema_version(api_client: TestClient) -> None:
    payload = _submission_payload("anonymous:request:v2-schema-bump")
    created = api_client.post("/v1/preference-profiles", json=payload)
    assert created.status_code == 201
    body = created.json()
    assert body["schema_version"] == "preference-profile-v2"
    assert body["questionnaire_version"] == "questionnaire-v2"
    assert body["scoring_version"] == "choice-bp-v2"
    assert set(body["answers"]) == {f"q{number}" for number in range(1, 13)}
