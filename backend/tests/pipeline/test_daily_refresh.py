from __future__ import annotations

import json
import logging
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from itda.cli import run_daily_glm_refresh
from itda.contracts.mvp_daily_refresh import DailyRefreshRunStatus
from itda.contracts.mvp_public_catalog import (
    PublicEvidenceInventory,
    PublicPlaceCatalog,
    PublicPlaceRelations,
)
from itda.pipeline.daily_refresh import due_run_date, next_run_at, run_daily_refresh
from tests.pipeline.test_daily_public_input import (
    SyntheticDailyProvider,
    SyntheticScoringTransport,
    _bundled_release,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
CATALOG = PublicPlaceCatalog.model_validate_json(
    (REPO_ROOT / "artifacts/public/catalog/public-place-catalog-v1.json").read_bytes()
)
EVIDENCE = PublicEvidenceInventory.model_validate_json(
    (REPO_ROOT / "artifacts/public/catalog/public-evidence-inventory-v1.json").read_bytes()
)
RELATIONS = PublicPlaceRelations.model_validate_json(
    (REPO_ROOT / "artifacts/public/catalog/public-place-relations-v1.json").read_bytes()
)


class SyntheticRefreshStore:
    def __init__(self, previous=None) -> None:
        self.previous = previous
        self.claimed: list[date] = []
        self.snapshots = []
        self.plans = []
        self.reservations = []
        self.attempts = []
        self.published = []
        self.activations: list[dict[str, object]] = []
        self.finished: list[dict[str, object]] = []
        self.collection_failures = []

    def claim(self, *, run_date: date, authority_sha256: str) -> bool:
        del authority_sha256
        self.claimed.append(run_date)
        return True

    def latest_snapshot(self):
        return self.previous

    def store_snapshot(self, snapshot) -> None:
        self.snapshots.append(snapshot)

    def baseline_snapshot(self):
        return self.previous if self.previous is not None else self.snapshots[0]

    def get_snapshot(self, sha):
        return next(
            (
                s
                for s in [self.previous, *self.snapshots]
                if s is not None and s.snapshot_sha256 == sha
            ),
            None,
        )

    def store_plan(self, plan) -> None:
        self.plans.append(plan)

    def reserve_call(self, *, run_date: date, event) -> int:
        self.reservations.append((run_date, event))
        return len(self.reservations)

    def finish_attempt(self, *, run_date: date, event, result_sha256=None) -> None:
        self.attempts.append((run_date, event, result_sha256))

    def publish(self, release) -> None:
        self.published.append(release)

    def activate(self, **fields: object) -> None:
        self.activations.append(fields)

    def finish(self, **fields: object) -> None:
        self.finished.append(fields)

    def record_collection_failure(self, *, run_date: date, failure) -> None:
        self.collection_failures.append((run_date, failure))


def test_kst_schedule_boundary_and_next_run_use_utc_outputs() -> None:
    before = datetime(2026, 9, 5, 22, 59, 59, tzinfo=UTC)
    at_eight = datetime(2026, 9, 5, 23, 0, 0, tzinfo=UTC)

    assert due_run_date(before) is None
    assert due_run_date(at_eight) == date(2026, 9, 6)
    assert next_run_at(before) == at_eight
    assert next_run_at(at_eight) == datetime(2026, 9, 6, 23, 0, tzinfo=UTC)


def test_first_complete_snapshot_records_baseline_without_glm_factory() -> None:
    store = SyntheticRefreshStore()
    scorer_constructions = 0

    def forbidden_scorer_factory():
        nonlocal scorer_constructions
        scorer_constructions += 1
        raise AssertionError("baseline must not construct GLM transport")

    outcome = run_daily_refresh(
        run_date=date(2026, 9, 6),
        collected_at=datetime(2026, 9, 5, 23, 0, tzinfo=UTC),
        catalog=CATALOG,
        evidence_inventory=EVIDENCE,
        relations=RELATIONS,
        provider=SyntheticDailyProvider(),
        store=store,  # type: ignore[arg-type]
        active_release_resolver=lambda: None,
        scoring_transport_factory=forbidden_scorer_factory,
    )

    assert outcome is not None
    assert outcome.status is DailyRefreshRunStatus.BASELINE_RECORDED
    assert outcome.call_count == 0
    assert scorer_constructions == 0
    assert len(store.snapshots) == 1
    assert store.finished[-1]["status"] is DailyRefreshRunStatus.BASELINE_RECORDED


def test_metadata_only_change_records_no_changes_without_glm_factory() -> None:
    baseline_store = SyntheticRefreshStore()
    baseline = run_daily_refresh(
        run_date=date(2026, 9, 5),
        collected_at=datetime(2026, 9, 4, 23, 0, tzinfo=UTC),
        catalog=CATALOG,
        evidence_inventory=EVIDENCE,
        relations=RELATIONS,
        provider=SyntheticDailyProvider(metadata_version="1"),
        store=baseline_store,  # type: ignore[arg-type]
        active_release_resolver=lambda: None,
        scoring_transport_factory=lambda: (_ for _ in ()).throw(AssertionError()),
    )
    assert baseline is not None
    previous = baseline_store.snapshots[0]
    store = SyntheticRefreshStore(previous=previous)
    scorer_constructions = 0

    def forbidden_scorer_factory():
        nonlocal scorer_constructions
        scorer_constructions += 1
        raise AssertionError("no-change run must not construct GLM transport")

    outcome = run_daily_refresh(
        run_date=date(2026, 9, 6),
        collected_at=datetime(2026, 9, 5, 23, 0, tzinfo=UTC),
        catalog=CATALOG,
        evidence_inventory=EVIDENCE,
        relations=RELATIONS,
        provider=SyntheticDailyProvider(metadata_version="2"),
        store=store,  # type: ignore[arg-type]
        active_release_resolver=_bundled_release,
        scoring_transport_factory=forbidden_scorer_factory,
    )

    assert outcome is not None
    assert outcome.status is DailyRefreshRunStatus.NO_CHANGES
    assert outcome.call_count == 0
    assert scorer_constructions == 0
    assert store.snapshots[0].snapshot_sha256 != previous.snapshot_sha256


def test_incomplete_collection_records_failure_without_glm_factory() -> None:
    target_content_id = next(
        row.source_id for row in CATALOG.places[0].provider_crosswalk if row.provider == "TOUR_API"
    )
    store = SyntheticRefreshStore()
    scorer_constructions = 0

    def forbidden_scorer_factory():
        nonlocal scorer_constructions
        scorer_constructions += 1
        raise AssertionError("incomplete collection must not construct GLM transport")

    outcome = run_daily_refresh(
        run_date=date(2026, 9, 6),
        collected_at=datetime(2026, 9, 5, 23, 0, tzinfo=UTC),
        catalog=CATALOG,
        evidence_inventory=EVIDENCE,
        relations=RELATIONS,
        provider=SyntheticDailyProvider(fail_content_id=target_content_id),
        store=store,  # type: ignore[arg-type]
        active_release_resolver=lambda: None,
        scoring_transport_factory=forbidden_scorer_factory,
    )

    assert outcome is not None
    assert outcome.status is DailyRefreshRunStatus.COLLECTION_INCOMPLETE
    assert outcome.call_count == 0
    assert scorer_constructions == 0
    assert store.snapshots == []
    assert len(store.collection_failures) == 1
    assert store.collection_failures[0][0] == date(2026, 9, 6)
    assert store.collection_failures[0][1].operation == "detailIntro2"


def test_preclaimed_recollection_skips_scheduled_claim() -> None:
    store = SyntheticRefreshStore()

    outcome = run_daily_refresh(
        run_date=date(2026, 9, 6),
        collected_at=datetime(2026, 9, 5, 23, 0, tzinfo=UTC),
        catalog=CATALOG,
        evidence_inventory=EVIDENCE,
        relations=RELATIONS,
        provider=SyntheticDailyProvider(),
        store=store,  # type: ignore[arg-type]
        active_release_resolver=lambda: None,
        scoring_transport_factory=lambda: (_ for _ in ()).throw(AssertionError()),
        preclaimed=True,
    )

    assert outcome is not None
    assert outcome.status is DailyRefreshRunStatus.BASELINE_RECORDED
    assert store.claimed == []


def _baseline_snapshot():
    baseline_store = SyntheticRefreshStore()
    outcome = run_daily_refresh(
        run_date=date(2026, 9, 5),
        collected_at=datetime(2026, 9, 4, 23, 0, tzinfo=UTC),
        catalog=CATALOG,
        evidence_inventory=EVIDENCE,
        relations=RELATIONS,
        provider=SyntheticDailyProvider(),
        store=baseline_store,  # type: ignore[arg-type]
        active_release_resolver=lambda: None,
        scoring_transport_factory=lambda: (_ for _ in ()).throw(AssertionError()),
    )
    assert outcome is not None
    return baseline_store.snapshots[0]


def _changed_provider() -> SyntheticDailyProvider:
    target_content_id = next(
        row.source_id for row in CATALOG.places[0].provider_crosswalk if row.provider == "TOUR_API"
    )
    return SyntheticDailyProvider(changed_content_id=target_content_id)


def test_changed_run_scores_publishes_and_activates_release() -> None:
    store = SyntheticRefreshStore(previous=_baseline_snapshot())
    transport = SyntheticScoringTransport()

    outcome = run_daily_refresh(
        run_date=date(2026, 9, 6),
        collected_at=datetime(2026, 9, 5, 23, 0, tzinfo=UTC),
        catalog=CATALOG,
        evidence_inventory=EVIDENCE,
        relations=RELATIONS,
        provider=_changed_provider(),
        store=store,  # type: ignore[arg-type]
        active_release_resolver=_bundled_release,
        scoring_transport_factory=lambda: transport,
    )

    assert outcome is not None
    assert outcome.status is DailyRefreshRunStatus.RELEASE_ACTIVATED
    assert outcome.changed_count == 1
    assert outcome.failed_count == 0
    assert outcome.call_count == 1
    assert outcome.release_sha256 == store.published[0].release_sha256
    assert len(store.plans) == 1
    assert len(store.reservations) == 1
    assert len(store.attempts) == 1
    assert store.attempts[0][1].status == "SUCCEEDED"
    assert store.attempts[0][2] is not None
    assert store.activations == [
        {
            "run_date": date(2026, 9, 6),
            "release_sha256": outcome.release_sha256,
            "expected_current": _bundled_release().release_sha256,
        }
    ]


def test_terminal_scoring_error_stops_without_release_publish() -> None:
    store = SyntheticRefreshStore(previous=_baseline_snapshot())
    transport = SyntheticScoringTransport(terminal_reason="GLM_HTTP_AUTH_REJECTED")

    outcome = run_daily_refresh(
        run_date=date(2026, 9, 6),
        collected_at=datetime(2026, 9, 5, 23, 0, tzinfo=UTC),
        catalog=CATALOG,
        evidence_inventory=EVIDENCE,
        relations=RELATIONS,
        provider=_changed_provider(),
        store=store,  # type: ignore[arg-type]
        active_release_resolver=_bundled_release,
        scoring_transport_factory=lambda: transport,
    )

    assert outcome is not None
    assert outcome.status is DailyRefreshRunStatus.SCORING_FAILED
    assert outcome.safe_reason == "GLM_HTTP_AUTH_REJECTED"
    assert outcome.call_count == 1
    assert len(store.reservations) == 1
    assert store.attempts[0][1].status == "FAILED"
    assert store.published == []
    assert store.activations == []


def test_changed_run_without_active_release_is_rejected_before_scoring() -> None:
    store = SyntheticRefreshStore(previous=_baseline_snapshot())

    outcome = run_daily_refresh(
        run_date=date(2026, 9, 6),
        collected_at=datetime(2026, 9, 5, 23, 0, tzinfo=UTC),
        catalog=CATALOG,
        evidence_inventory=EVIDENCE,
        relations=RELATIONS,
        provider=_changed_provider(),
        store=store,  # type: ignore[arg-type]
        active_release_resolver=lambda: None,
        scoring_transport_factory=SyntheticScoringTransport,
    )

    assert outcome is not None
    assert outcome.status is DailyRefreshRunStatus.RELEASE_REJECTED
    assert outcome.safe_reason == "ACTIVE_RELEASE_MISSING"
    assert outcome.call_count == 0
    assert store.plans == []
    assert store.reservations == []
    assert store.published == []
    assert store.activations == []


def test_same_day_running_ledger_is_interrupted_without_provider_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Reader:
        def status(self):
            return type(
                "Status",
                (),
                {
                    "run_date": date(2026, 9, 6),
                    "status": DailyRefreshRunStatus.RUNNING,
                },
            )()

    class Store:
        def __init__(self) -> None:
            self.interrupted: list[date] = []

        def interrupt(self, *, run_date: date) -> None:
            self.interrupted.append(run_date)

    store = Store()
    monkeypatch.setattr(
        run_daily_glm_refresh,
        "LiveDailyTourApiProvider",
        lambda **_fields: (_ for _ in ()).throw(
            AssertionError("same-day RUNNING ledger must not construct provider")
        ),
    )

    run_daily_glm_refresh._run_one(
        run_date=date(2026, 9, 6),
        store=store,  # type: ignore[arg-type]
        reader=Reader(),  # type: ignore[arg-type]
        active_resolver=lambda: None,  # type: ignore[arg-type]
        catalog=CATALOG,
        evidence=EVIDENCE,
        relations=RELATIONS,
        tour_api_key="synthetic-not-a-secret",
    )

    assert store.interrupted == [date(2026, 9, 6)]


def test_recollection_command_uses_preclaimed_run_and_completes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = type(
        "Command",
        (),
        {
            "command_id": "12345678-1234-4234-9234-123456789abc",
            "run_date": date(2026, 9, 6),
        },
    )()

    class Store:
        def __init__(self) -> None:
            self.completed: list[dict[str, object]] = []

        def claim_recollection(self, *, lease_seconds: int):
            assert lease_seconds == 60
            return command

        def complete_recollection(self, **fields: object) -> None:
            self.completed.append(fields)

    class Reader:
        def status(self):
            return type(
                "Status",
                (),
                {
                    "run_date": date(2026, 9, 6),
                    "status": DailyRefreshRunStatus.NO_CHANGES,
                    "safe_reason": None,
                },
            )()

    calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        run_daily_glm_refresh,
        "_run_one",
        lambda **fields: calls.append(fields),
    )
    store = Store()

    assert run_daily_glm_refresh._run_recollection_command(
        store=store,  # type: ignore[arg-type]
        reader=Reader(),  # type: ignore[arg-type]
        active_resolver=lambda: None,  # type: ignore[arg-type]
        catalog=CATALOG,
        evidence=EVIDENCE,
        relations=RELATIONS,
        tour_api_key="synthetic-not-a-secret",
    )
    assert calls[0]["preclaimed"] is True
    assert calls[0]["run_date"] == date(2026, 9, 6)
    assert store.completed == [
        {
            "command_id": command.command_id,
            "status": "SUCCEEDED",
            "safe_reason": None,
        }
    ]


def test_scheduler_sleep_is_bounded_to_command_poll_interval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slept: list[float] = []
    monkeypatch.setattr(run_daily_glm_refresh.time, "sleep", slept.append)

    run_daily_glm_refresh._sleep_until(datetime.now(UTC) + timedelta(days=1))

    assert slept == [15.0]


def test_scheduler_and_public_deploy_defaults_use_current_availability_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ast

    from itda.contracts.mvp_daily_refresh import (
        DAILY_REFRESH_AUTHORITY,
        DAILY_REFRESH_AUTHORITY_V2,
    )

    authority = DAILY_REFRESH_AUTHORITY_V2.authority_sha256
    monkeypatch.setenv("ITDA_DAILY_GLM_REFRESH_ENABLED", "1")
    monkeypatch.setenv("ITDA_DAILY_GLM_REFRESH_AUTHORITY_SHA256", authority)
    run_daily_glm_refresh._validate_authority()
    monkeypatch.setenv(
        "ITDA_DAILY_GLM_REFRESH_AUTHORITY_SHA256", DAILY_REFRESH_AUTHORITY.authority_sha256
    )
    with pytest.raises(RuntimeError, match="authority rejected"):
        run_daily_glm_refresh._validate_authority()

    defaults = (REPO_ROOT / "deploy/env.example").read_text()
    assert f"ITDA_DAILY_GLM_REFRESH_AUTHORITY_SHA256={authority}" in defaults
    deploy_script = (REPO_ROOT / "deploy/deploy-swarm-stack.sh").read_text()
    assert f'"$ITDA_DAILY_GLM_REFRESH_AUTHORITY_SHA256" = "{authority}"' in deploy_script
    generator = ast.parse((REPO_ROOT / "scripts/generate_deploy_env.py").read_text())
    constants = {
        target.id: ast.literal_eval(node.value)
        for node in generator.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name) and target.id == "_DAILY_REFRESH_AUTHORITY_SHA256"
    }
    assert constants["_DAILY_REFRESH_AUTHORITY_SHA256"] == authority


def test_deferred_glm_transport_resolves_secret_only_after_call_reservation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class Transport:
        def __init__(self, api_key: str) -> None:
            assert api_key == "synthetic-key"
            events.append("transport")

        def score(self, request, *, timeout_seconds: int, max_tokens: int) -> bytes:
            del request, timeout_seconds, max_tokens
            raise AssertionError("synthetic transport should not be called directly")

        def close(self) -> None:
            pass

    monkeypatch.setattr(
        run_daily_glm_refresh,
        "_secret",
        lambda *_names: events.append("secret") or "synthetic-key",
    )
    monkeypatch.setattr(run_daily_glm_refresh, "GlmCodingScoringTransport", Transport)
    transport = run_daily_glm_refresh.DeferredGlmTransport()

    assert events == []
    request = _baseline_snapshot().places[0].request
    events.append("reservation")
    with pytest.raises(AssertionError, match="should not be called directly"):
        transport.score(request, timeout_seconds=1, max_tokens=1)

    assert events == ["reservation", "secret", "transport"]


@pytest.mark.parametrize("initial_level", (logging.INFO, logging.DEBUG))
def test_scheduler_logging_suppresses_http_request_urls(
    caplog: pytest.LogCaptureFixture,
    initial_level: int,
) -> None:
    with (
        caplog.at_level(initial_level),
        caplog.at_level(initial_level, logger="httpx"),
        caplog.at_level(initial_level, logger="httpcore"),
    ):
        run_daily_glm_refresh._configure_logging()
        transport = httpx.MockTransport(lambda _request: httpx.Response(200, json={}))
        with httpx.Client(transport=transport) as client:
            response = client.get(
                "https://example.invalid/detailCommon2",
                params={"serviceKey": "synthetic-log-test-key"},
            )
        assert response.status_code == 200
        logging.getLogger("httpcore.connection").debug(
            "synthetic transport detail: serviceKey=synthetic-log-test-key"
        )
        run_daily_glm_refresh._safe_log("daily_glm_refresh_waiting", call_count=0)
        logging.getLogger("httpx").warning("synthetic httpx warning")
        logging.getLogger("httpcore").warning("synthetic httpcore warning")

    assert "HTTP Request:" not in caplog.text
    assert "serviceKey" not in caplog.text
    assert "synthetic-log-test-key" not in caplog.text
    assert "example.invalid" not in caplog.text
    assert "daily_glm_refresh_waiting" in caplog.text
    assert "synthetic httpx warning" in caplog.text
    assert "synthetic httpcore warning" in caplog.text


def test_safe_log_emits_only_closed_allowlist(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="itda.daily_glm_refresh"):
        run_daily_glm_refresh._safe_log(
            "daily_glm_refresh_finished",
            run_date=date(2026, 9, 6),
            status=DailyRefreshRunStatus.NO_CHANGES,
            call_count=0,
            authorization="forbidden-authorization",
            provider_body="forbidden-provider-body",
            secret="forbidden-secret",
        )

    payload = json.loads(caplog.records[-1].getMessage())
    assert payload == {
        "call_count": 0,
        "event": "daily_glm_refresh_finished",
        "run_date": "2026-09-06",
        "status": "NO_CHANGES",
    }
    assert "forbidden" not in caplog.records[-1].getMessage()
