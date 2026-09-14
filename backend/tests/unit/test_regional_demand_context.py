"""Aggregate demand codes retain exact official index values, without live requests."""

from __future__ import annotations

import copy
import json
from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path

import httpx
import pytest

from itda.collectors.base import RequestPolicy
from itda.collectors.kto_demand import RegionalDemandClient
from itda.contracts.source_assessment import SourceService
from itda.contracts.trip_context import RegionalDemandContext, RegionalDemandMeasure
from itda.domain.canonical import canonical_sha256
from itda.tourism.accessibility import CanonicalTourismPlace
from itda.tourism.temporal import TemporalContextService, TemporalPolicy

# Sanitized actual 2026-09-09 capture 7bfad8a2... and archived UNKNOWN rows.
# Keep tests independent of local research/report output directories.
CAPTURE = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures/regional-demand-context.json").read_text()
)
NOW = datetime(2026, 9, 9, tzinfo=UTC)


@pytest.fixture(autouse=True)
def mocked_transport_only(monkeypatch):
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)


def _service(*, stay_changes=None, duplicate=False):
    requests = []

    def respond(request):
        operation = request.url.path.rsplit("/", 1)[-1]
        prefix, code = (
            ("tarSjrnDsIx", "21") if operation == "areaTarSjrnDsList" else ("tarExpDsIx", "22")
        )
        requests.append((operation, request.url.params.get(prefix + "Cd")))
        capture = next(
            row
            for row in CAPTURE["checks"]
            if row["operation"] == operation
            and row["params"]["baseYm"] == request.url.params["baseYm"]
        )
        payload = copy.deepcopy(capture["payload"])
        row = payload["response"]["body"]["items"]["item"][0]
        # Actual provider failure mode: an omitted indicator selector gives a
        # misleading zero despite an otherwise successful response envelope.
        if request.url.params.get(prefix + "Cd") != code:
            row[prefix + "Val"] = "0"
        if operation == "areaTarSjrnDsList":
            row.update(stay_changes or {})
            if duplicate:
                payload["response"]["body"]["items"]["item"].append(copy.deepcopy(row))
                payload["response"]["body"]["totalCount"] = 2
        return httpx.Response(200, json=payload)

    client = RegionalDemandClient(
        service_key="synthetic-demand-test-key",
        http_client=httpx.Client(transport=httpx.MockTransport(respond)),
        clock=lambda: NOW,
        policy=RequestPolicy(max_attempts=1),
    )
    return TemporalContextService(
        places=(
            CanonicalTourismPlace(place_id="demand:region", name_ko="경주시", region_code="47130"),
        ),
        demand=client,
        clock=lambda: NOW,
        policy=TemporalPolicy(enabled=True),
    ), requests


def _context(service, month="202607"):
    return service.get_context(place_ids=(), trip_date=date(2026, 9, 10), demand_month=month)


@pytest.mark.parametrize(
    "month,stay,spend", [("202607", "102.99", "77.92"), ("202509", "91", "74.48")]
)
def test_explicit_aggregate_codes_preserve_actual_decimal_indices(month, stay, spend):
    service, requests = _service()
    context = _context(service, month)
    assert sorted(requests) == [("areaTarExpDsList", "22"), ("areaTarSjrnDsList", "21")]
    assert [row.state for row in context.demand] == ["AVAILABLE", "AVAILABLE"]
    assert [row.reason for row in context.demand] == ["NONE", "NONE"]
    assert [row.measures[0].value for row in context.demand] == [Decimal(stay), Decimal(spend)]
    assert [row.measures[0].raw_value for row in context.demand] == [stay, spend]
    assert [row.measures[0].indicator_code for row in context.demand] == ["21", "22"]
    assert [row.measures[0].indicator_name for row in context.demand] == [
        "관광체류강도",
        "관광소비강도",
    ]
    assert all(row.measures[0].unit == "TOURISM_DEMAND_INDEX" for row in context.demand)
    assert all(row.base_month == month and row.region_code == "47130" for row in context.demand)
    assert all(row.source_snapshot_sha256 and row.receipts for row in context.demand)
    assert context.ranking_effect == "NONE" and context.usage == "INFORMATION_ONLY"
    assert context.forecasts == () and context.visitors.points == ()
    assert service.replay(context.model_dump(mode="json")) == context
    assert len(requests) == 2


def test_omitted_selector_zero_is_not_promoted_to_available():
    service, requests = _service()
    snapshot = service.collect_source_batch(
        SourceService.DEMAND,
        "areaTarSjrnDsList",
        {"baseYm": "202607", "areaCd": "47", "signguCd": "47130"},
        service.demand,
    )
    unverified = service._demand("REGIONAL_STAY_INTENSITY", "202607", NOW, snapshot)
    assert unverified.state == "UNKNOWN" and unverified.reason == "UNIT_UNVERIFIED"
    assert unverified.measures[0].raw_value == "0" and unverified.measures[0].value is None
    assert requests == [("areaTarSjrnDsList", None)]
    actual = _context(service).demand[0]
    assert actual.measures[0].value == Decimal("102.99")


@pytest.mark.parametrize("raw", ["0", "-0.25", "100000000000.000001"])
def test_available_index_is_finite_signed_decimal_without_invented_range(raw):
    service, _ = _service(stay_changes={"tarSjrnDsIxVal": raw})
    measure = _context(service).demand[0].measures[0]
    assert measure.state == "AVAILABLE" and measure.value == Decimal(raw)
    assert measure.raw_value == raw


@pytest.mark.parametrize(
    "changes",
    [
        {"areaCd": "11"},
        {"signguCd": "11110"},
        {"baseYm": "202606"},
        {"tarSjrnDsIxCd": "22"},
        {"tarSjrnDsIxCd": ""},
        {"tarSjrnDsIxNm": "다른 지표"},
        {"tarSjrnDsIxVal": ""},
        {"tarSjrnDsIxVal": "NaN"},
        {"tarSjrnDsIxVal": "Infinity"},
        {"tarSjrnDsIxVal": "-Infinity"},
        {"tarSjrnDsIxVal": "102.99%"},
        {"tarSjrnDsIxVal": 102.99},
        {"tarSjrnDsIxVal": True},
    ],
)
def test_wrong_identity_or_malformed_value_remains_unknown(changes):
    service, _ = _service(stay_changes=changes)
    context = _context(service).demand[0]
    assert context.state == "UNKNOWN"
    assert not context.measures or all(row.value is None for row in context.measures)


def test_duplicate_aggregate_is_ambiguous_and_subindicator_unit_stays_unverified():
    service, _ = _service(duplicate=True)
    assert _context(service).demand[0].reason == "AMBIGUOUS_MATCH"
    service, _ = _service(stay_changes={"tarSjrnDsIxCd": "2101", "tarSjrnDsIxNm": "체류 하위 지표"})
    context = _context(service).demand[0]
    assert context.state == "UNKNOWN" and context.reason == "UNIT_UNVERIFIED"
    assert context.measures[0].unit == "UNVERIFIED_PROVIDER_UNIT"


@pytest.mark.parametrize(
    "change",
    [
        {"value": "102.98"},
        {"value": None},
        {"raw_value": "NaN"},
        {"unit": "UNVERIFIED_PROVIDER_UNIT"},
        {"indicator_code": "2101"},
        {"indicator_name": "관광소비강도"},
        {"state": "UNKNOWN"},
    ],
)
def test_measure_contract_rejects_numeric_or_identity_drift(change):
    service, _ = _service()
    payload = _context(service).demand[0].measures[0].model_dump(mode="json")
    with pytest.raises(ValueError):
        RegionalDemandMeasure.model_validate(payload | change)


@pytest.mark.parametrize(
    "change",
    [
        {"source_snapshot_sha256": None},
        {"retrieved_at": None},
        {"expires_at": None},
        {"expires_at": NOW.isoformat()},
        {"base_month": "202606"},
        {"receipts": []},
        {"reason": "UNIT_UNVERIFIED"},
    ],
)
def test_available_context_requires_period_source_and_time_binding(change):
    service, _ = _service()
    payload = _context(service).demand[0].model_dump(mode="json")
    with pytest.raises(ValueError):
        RegionalDemandContext.model_validate(payload | change)


@pytest.mark.parametrize(
    "key,value",
    [("baseYm", "202606"), ("areaCd", "11"), ("signguCd", "11110"), ("tarSjrnDsIxCd", "2101")],
)
def test_available_context_rejects_wrong_receipt_request_scope(key, value):
    service, _ = _service()
    payload = _context(service).demand[0].model_dump(mode="json")
    payload["receipts"][0]["request_scope"][key] = value
    with pytest.raises(ValueError):
        RegionalDemandContext.model_validate(payload)


def test_old_unverified_measure_defaults_and_frozen_context_remain_byte_compatible():
    old = {"indicator_code": "2101", "indicator_name": "이전 미확인 지표", "raw_value": "12.5"}
    assert RegionalDemandMeasure.model_validate(old).model_dump(mode="json") == old | {
        "value": None,
        "state": "UNKNOWN",
        "reason": "UNIT_UNVERIFIED",
        "unit": "UNVERIFIED_PROVIDER_UNIT",
    }
    frozen = CAPTURE["legacy_demand_contexts"]
    restored = [RegionalDemandContext.model_validate(row).model_dump(mode="json") for row in frozen]
    assert restored == frozen
    assert canonical_sha256(restored) == CAPTURE["legacy_demand_sha256"]


@pytest.mark.parametrize("other_service", [False, True])
def test_available_context_rejects_wrong_receipt_service_or_operation(other_service):
    service, _ = _service()
    payload = _context(service).demand[0].model_dump(mode="json")
    if other_service:
        payload["receipts"][0].update(
            service="DataLabService", operation="locgoRegnVisitrDDList", dataset_id="15101972"
        )
    else:
        payload["receipts"][0]["operation"] = "areaTarExpDsList"
    with pytest.raises(ValueError):
        RegionalDemandContext.model_validate(payload)


def test_regional_measure_cannot_be_attached_as_place_ranking_input():
    from itda.contracts.grounded_run import GroundedPreference
    from tests.unit.test_grounded_recommendation import preference

    service, _ = _service()
    context = _context(service)
    assert context.usage == "INFORMATION_ONLY" and context.ranking_effect == "NONE"
    assert {row.scope for row in context.demand} == {"REGION"}
    payload = preference().model_dump(mode="json")
    with pytest.raises(ValueError):
        GroundedPreference.model_validate(
            payload | {"regional_demand": context.demand[0].model_dump(mode="json")}
        )
