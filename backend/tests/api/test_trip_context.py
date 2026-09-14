"""Temporal API tracer with real service and official response transport shapes.

The phase07 production route composition is owned by the root integration task.
This small FastAPI adapter proves date validation, scoped service output, cache,
and decimal JSON contracts without implying it is the production route already.
"""

from datetime import date
from typing import Annotated

import pytest
from fastapi import FastAPI, HTTPException, Query
from fastapi.testclient import TestClient

from itda.contracts.trip_context import TripTemporalContext
from itda.tourism.temporal import TemporalContextService
from tests.unit.test_temporal_context import make_service


def app_for(service: TemporalContextService) -> FastAPI:
    app = FastAPI()

    @app.get("/trip-context", response_model=TripTemporalContext)
    def context(
        trip_date: date,
        place_id: Annotated[list[str], Query()],
        visitor_start: date | None = None,
        visitor_end: date | None = None,
        demand_month: str | None = None,
    ) -> TripTemporalContext:
        try:
            return service.get_context(
                place_ids=tuple(place_id),
                trip_date=trip_date,
                visitor_start=visitor_start,
                visitor_end=visitor_end,
                demand_month=demand_month,
            )
        except ValueError as error:
            raise HTTPException(422, "temporal context request is invalid") from error

    return app


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)


def test_forecast_api_returns_source_window_decimal_and_no_rank_effect() -> None:
    service, state, _ = make_service()
    with TestClient(app_for(service)) as client:
        result = client.get(
            "/trip-context",
            params={
                "place_id": "place:gampo",
                "trip_date": "2026-09-10",
                "visitor_start": "2026-07-01",
                "visitor_end": "2026-07-01",
                "demand_month": "202607",
            },
        )
        assert result.status_code == 200, result.text
        body = result.json()
        assert body["usage"] == "INFORMATION_ONLY" and body["ranking_effect"] == "NONE"
        forecast = body["forecasts"][0]
        assert forecast["value"] == "24.16" and forecast["window_start"] == "2026-09-08"
        assert forecast["window_end"] == "2026-10-07" and forecast["provider_issue_date"] is None
        assert forecast["receipts"][0]["dataset_id"] == "15128555"
        assert body["visitors"]["points"][2]["value"] == "3570.8999999999996"
        assert all(row["reason"] == "AUTHORIZATION_UNAVAILABLE" for row in body["demand"])
        calls = len(state["calls"])
        assert (
            client.get(
                "/trip-context", params={"place_id": "place:gampo", "trip_date": "2026-09-11"}
            ).status_code
            == 200
        )
        assert len(state["calls"]) == calls


def test_outside_window_is_typed_unknown_and_bad_identity_or_period_rejected() -> None:
    service, state, _ = make_service()
    with TestClient(app_for(service)) as client:
        result = client.get(
            "/trip-context", params={"place_id": "place:gampo", "trip_date": "2026-10-08"}
        )
        assert result.status_code == 200
        assert result.json()["forecasts"][0]["reason"] == "OUT_OF_WINDOW"
        assert result.json()["forecasts"][0]["value"] is None
        calls = len(state["calls"])
        for invalid in (
            {"place_id": "place:other"},
            {"trip_date": "2026-02-31"},
            {"visitor_start": "2026-07-01"},
            {"demand_month": "202613"},
            {"visitor_start": "2026-01-01", "visitor_end": "2026-07-01"},
        ):
            result = client.get(
                "/trip-context",
                params={"place_id": "place:gampo", "trip_date": "2026-09-10", **invalid},
            )
            assert result.status_code == 422
        assert len(state["calls"]) == calls
