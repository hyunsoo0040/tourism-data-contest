from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from fastapi.testclient import TestClient

from itda.api.dependencies import get_daily_release_overlay_reader
from itda.api.main import create_app
from itda.contracts.mvp_daily_refresh import (
    DailyCollectionFailureProjection,
    DailyGlmAttemptProjection,
    DailyRecollectionCommandProjection,
    DailyRecollectionEligibility,
    DailyRefreshExecutionProjection,
)
from itda.db.mvp_release_overlay import (
    DailyExecutionDetailRecord,
    DailyOperationsOverviewRecord,
    DailyRefreshConflict,
    DailyRefreshStoreError,
)

NOW = datetime(2026, 9, 6, 8, tzinfo=UTC)
RUN_DATE = date(2026, 9, 6)
COMMAND_ID = "12345678-1234-4234-9234-123456789abc"
PLACE_ID = f"public:gyeongju:{'1' * 64}"


def _execution() -> DailyRefreshExecutionProjection:
    return DailyRefreshExecutionProjection(
        run_date=RUN_DATE,
        execution_sequence=0,
        kind="SCHEDULED",
        command_id=None,
        status="COLLECTION_INCOMPLETE",
        changed_count=0,
        failed_count=0,
        call_count=0,
        active_release_sha256=None,
        safe_reason="TOUR_API_COLLECTION_FAILED",
        started_at=NOW,
        updated_at=NOW,
        finished_at=NOW,
    )


def _command() -> DailyRecollectionCommandProjection:
    return DailyRecollectionCommandProjection(
        command_id=COMMAND_ID,
        run_date=RUN_DATE,
        idempotency_key="daily-recollect-20260906",
        status="REQUESTED",
        execution_sequence=None,
        safe_reason=None,
        requested_at=NOW,
        claimed_at=None,
        lease_expires_at=None,
        finished_at=None,
    )


class OperationsReader:
    def __init__(self) -> None:
        self.requested = False

    def operations_overview(self) -> DailyOperationsOverviewRecord:
        return DailyOperationsOverviewRecord(
            execution=_execution(),
            active_release_sha256="a" * 64,
            recollection=DailyRecollectionEligibility(
                eligible=True,
                safe_reason="RECOLLECTION_ALLOWED",
            ),
            pending_command_id=None,
        )

    def execution_history(
        self,
        *,
        days: int,
    ) -> tuple[DailyRefreshExecutionProjection, ...]:
        assert days == 30
        return (_execution(),)

    def execution_detail(
        self,
        *,
        run_date: date,
        execution_sequence: int,
    ) -> DailyExecutionDetailRecord | None:
        assert run_date == RUN_DATE
        assert execution_sequence == 0
        return DailyExecutionDetailRecord(
            execution=_execution(),
            collection_failures=(
                DailyCollectionFailureProjection(
                    place_id=PLACE_ID,
                    operation="detailIntro2",
                    failure_category="PROVIDER_TRANSPORT",
                    failure_code="PROVIDER_UNAVAILABLE",
                    execution_sequence=0,
                    occurred_at=NOW,
                ),
            ),
            attempts=(
                DailyGlmAttemptProjection(
                    run_date=RUN_DATE,
                    execution_sequence=0,
                    place_id=PLACE_ID,
                    attempt_number=1,
                    status="FAILED",
                    safe_reason="GLM_TIMEOUT",
                    result_sha256=None,
                    reserved_at=NOW - timedelta(seconds=2),
                    finished_at=NOW,
                ),
            ),
        )

    def request_recollection(
        self,
        *,
        run_date: date,
        idempotency_key: str,
    ) -> DailyRecollectionCommandProjection:
        assert run_date == RUN_DATE
        assert idempotency_key == "daily-recollect-20260906"
        self.requested = True
        return _command()

    def recollection_command(
        self,
        *,
        command_id: str,
    ) -> DailyRecollectionCommandProjection | None:
        return _command() if command_id == COMMAND_ID else None


def _client(reader: object) -> tuple[TestClient, object]:
    application = create_app()
    application.dependency_overrides[get_daily_release_overlay_reader] = lambda: reader
    return TestClient(application), application


def test_operations_overview_history_detail_and_command_projection() -> None:
    reader = OperationsReader()
    client, application = _client(reader)
    try:
        overview = client.get("/internal/operations/daily-glm/api/overview")
        history = client.get("/internal/operations/daily-glm/api/history?days=30")
        detail = client.get(
            "/internal/operations/daily-glm/api/history/2026-09-06?execution_sequence=0"
        )
        command = client.get(f"/internal/operations/daily-glm/api/commands/{COMMAND_ID}")
    finally:
        application.dependency_overrides.clear()

    assert overview.status_code == 200
    assert overview.json()["recollection"] == {
        "eligible": True,
        "safe_reason": "RECOLLECTION_ALLOWED",
    }
    assert overview.json()["active_release_sha256"] == "a" * 64
    assert history.status_code == 200
    assert len(history.json()["executions"]) == 1
    assert detail.status_code == 200
    assert detail.json()["collection_failures"][0] == {
        "schema_version": "mvp-daily-collection-failure.v1",
        "place_id": PLACE_ID,
        "operation": "detailIntro2",
        "failure_category": "PROVIDER_TRANSPORT",
        "failure_code": "PROVIDER_UNAVAILABLE",
        "execution_sequence": 0,
        "occurred_at": "2026-09-06T08:00:00Z",
    }
    assert detail.json()["attempts"][0]["safe_reason"] == "GLM_TIMEOUT"
    assert command.status_code == 200
    assert command.json()["command_id"] == COMMAND_ID


def test_operations_recollection_requires_same_origin(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("ITDA_CANONICAL_APP_ORIGIN", "https://it-da.app")
    reader = OperationsReader()
    client, application = _client(reader)
    payload = {
        "schema_version": "mvp-daily-recollection-command-request.v1",
        "run_date": "2026-09-06",
        "idempotency_key": "daily-recollect-20260906",
    }
    try:
        denied = client.post(
            "/internal/operations/daily-glm/api/commands/recollect",
            headers={"Origin": "https://attacker.example"},
            json=payload,
        )
        accepted = client.post(
            "/internal/operations/daily-glm/api/commands/recollect",
            headers={
                "Origin": "https://it-da.app",
                "Sec-Fetch-Site": "same-origin",
            },
            json=payload,
        )
    finally:
        application.dependency_overrides.clear()

    assert denied.status_code == 403
    assert accepted.status_code == 202
    assert reader.requested is True


def test_operations_conflict_and_store_failure_are_redacted(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("ITDA_CANONICAL_APP_ORIGIN", "https://it-da.app")

    class FailingReader(OperationsReader):
        def request_recollection(self, **_fields: object) -> DailyRecollectionCommandProjection:
            raise DailyRefreshConflict("postgresql://private-user:private-password@host")

        def execution_history(self, *, days: int) -> tuple[DailyRefreshExecutionProjection, ...]:
            raise DailyRefreshStoreError("provider-body-private")

    client, application = _client(FailingReader())
    try:
        conflict = client.post(
            "/internal/operations/daily-glm/api/commands/recollect",
            headers={"Origin": "https://it-da.app"},
            json={
                "schema_version": "mvp-daily-recollection-command-request.v1",
                "run_date": "2026-09-06",
                "idempotency_key": "daily-recollect-20260906",
            },
        )
        unavailable = client.get("/internal/operations/daily-glm/api/history")
    finally:
        application.dependency_overrides.clear()

    assert conflict.status_code == 409
    assert conflict.json() == {"detail": "daily GLM recollection rejected"}
    assert unavailable.status_code == 503
    assert unavailable.json() == {"detail": "daily GLM operations unavailable"}
    assert "private" not in conflict.text + unavailable.text


def test_operations_availability_counts_and_safe_exclusion_names() -> None:
    from itda.contracts.mvp_daily_refresh import (
        DailyExcludedPlaceProjection,
        DailyRefreshRunStatus,
    )
    from tests.pipeline.test_daily_refresh import CATALOG

    place = CATALOG.places[0]
    content_id = next(r.source_id for r in place.provider_crosswalk if r.provider == "TOUR_API")

    class AvailabilityReader(OperationsReader):
        def execution_detail(self, *, run_date, execution_sequence):
            record = super().execution_detail(
                run_date=run_date,
                execution_sequence=execution_sequence,
            )
            return DailyExecutionDetailRecord(
                execution=record.execution.model_copy(
                    update={
                        "status": DailyRefreshRunStatus.RELEASE_REJECTED,
                        "available_count": 79,
                        "information_unavailable_count": 21,
                        "event_ended_count": 0,
                    }
                ),
                collection_failures=(),
                attempts=(),
                excluded=(
                    DailyExcludedPlaceProjection(
                        place_id=place.place_id,
                        content_id=content_id,
                        state="INFORMATION_UNAVAILABLE",
                        safe_reason="COMMON_INFORMATION_UNAVAILABLE",
                        event_end_date=None,
                    ),
                ),
            )

    client, application = _client(AvailabilityReader())
    try:
        response = client.get("/internal/operations/daily-glm/api/history/2026-09-06")
    finally:
        application.dependency_overrides.clear()
    assert response.status_code == 200
    payload = response.json()
    assert payload["execution"]["available_count"] == 79
    assert payload["execution"]["information_unavailable_count"] == 21
    assert payload["execution"]["event_ended_count"] == 0
    assert payload["collection_failures"] == []
    assert payload["excluded"] == [
        {
            "place_id": place.place_id,
            "content_id": content_id,
            "place_name_ko": place.name_ko,
            "state": "INFORMATION_UNAVAILABLE",
            "safe_reason": "COMMON_INFORMATION_UNAVAILABLE",
            "event_end_date": None,
        }
    ]
