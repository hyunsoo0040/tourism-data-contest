"""Real batch/cache and PostgreSQL pair guards; all provider data is synthetic."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from threading import Lock

import httpx
import pytest

from itda.cli.analyze_grounded_places import run_batch
from itda.collectors.base import RequestPolicy
from itda.collectors.kto import KorService2Client
from itda.collectors.odii import OdiiClient
from itda.collectors.tourism_photo import TourismPhotoGalleryClient
from itda.contracts.mvp_place_scoring import SCORING_DIMENSIONS
from itda.contracts.source_assessment import SourceService
from itda.db.assessment_release import AssessmentReleaseRepository, load_candidate_from_directory
from itda.db.session import create_database_engine, create_session_factory
from itda.pipeline.daily_refresh import due_run_date, next_run_at
from itda.pipeline.destination_evidence import OfficialSourceCache
from itda.pipeline.grounded_daily_refresh import (
    PromotionEvidence,
    read_promotion_evidence,
    run_grounded_daily,
)
from itda.pipeline.grounded_place_scoring import GroundedTextProvider
from tests.contract.test_mvp_scored_release import release
from tests.integration.test_grounded_release_pairs import gate_fixture, report_fixtures
from tests.integration.test_recommendation_runs import _migrate
from tests.integration.test_source_grounding_tracer import _synthetic_catalog


@pytest.fixture(scope="module")
def pair_store(postgres_harness):
    _migrate(postgres_harness)
    engine = create_database_engine(postgres_harness.dsns["admin"])
    yield AssessmentReleaseRepository(create_session_factory(engine))
    engine.dispose()


@pytest.fixture
def harness(tmp_path, pair_store, monkeypatch):
    for name in ("CI", "ITDA_NO_NETWORK"):
        monkeypatch.delenv(name, raising=False)
    catalog = _synthetic_catalog()
    raw = release(80)
    clock = [datetime.now(UTC)]
    counters = {"source": 0, "model": 0, "active": 0, "peak": 0}
    lock = Lock()

    def source_transport(request):
        with lock:
            counters["source"] += 1
        operation = request.url.path.rsplit("/", 1)[-1]
        rows = []
        if operation == "detailCommon2":
            index = int(request.url.params["contentId"])
            place = catalog.places[index]
            rows = [
                {
                    "contentid": str(index),
                    "title": place.name_ko,
                    "mapx": str(place.longitude),
                    "mapy": str(place.latitude),
                    "overview": "합성 자료: 전통 건축의 이야기와 "
                    "눈에 띄는 색감이 있는 관광 장소입니다.",
                }
            ]
        return httpx.Response(
            200,
            json={
                "response": {
                    "header": {"resultCode": "0000", "resultMsg": "OK"},
                    "body": {"items": {"item": rows}, "totalCount": len(rows)},
                }
            },
        )

    http = httpx.Client(transport=httpx.MockTransport(source_transport))
    client_args = dict(
        service_key="unit-source-key-never-reflected",
        http_client=http,
        policy=RequestPolicy(max_attempts=1),
        clock=lambda: clock[0],
    )
    clients = {
        SourceService.TOUR: KorService2Client(**client_args),
        SourceService.ODII: OdiiClient(**client_args),
        SourceService.GALLERY: TourismPhotoGalleryClient(**client_args),
    }
    cache = OfficialSourceCache(tmp_path / "cache", clients=clients, live=True, ttl_days=0)

    def model_transport(request):
        with lock:
            counters["model"] += 1
            counters["active"] += 1
            counters["peak"] = max(counters["peak"], counters["active"])
        try:
            user = json.loads(json.loads(request.content)["messages"][1]["content"])
            evidence = user["evidence"][0]
            wire = {
                "independent_axes": {"H": 50, "E": 50, "R": 0},
                "judgments": [
                    {
                        "dimension": key,
                        "state": "SUPPORTED" if key in {"H1", "H2", "E1", "E2"} else "UNKNOWN",
                        "value": 2 if key in {"H1", "H2", "E1", "E2"} else None,
                        "citations": [
                            {"evidence_id": evidence["evidence_id"], "quote": evidence["excerpt"]}
                        ]
                        if key in {"H1", "H2", "E1", "E2"}
                        else [],
                        "reason": "합성 검증 판단",
                    }
                    for key in SCORING_DIMENSIONS[3:]
                ],
            }
            return httpx.Response(
                200,
                json={
                    "model": "glm-5.3-flash",
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {"content": json.dumps(wire, ensure_ascii=False)},
                        }
                    ],
                    "usage": {"total_tokens": 2},
                },
            )
        finally:
            with lock:
                counters["active"] -= 1

    provider = GroundedTextProvider(
        api_key="unit-model-key-never-reflected",
        cache_version="v2",
        transport=httpx.MockTransport(model_transport),
    )
    kwargs = dict(
        root=tmp_path / "daily",
        catalog=catalog,
        store=pair_store,
        cache=cache,
        text_provider=provider,
        mood_provider=None,
        raw_release_resolver=lambda: raw,
        workers=4,
        clock=lambda: clock[0],
    )
    yield kwargs, counters, clock, raw
    http.close()


def measured(candidate):
    reports = report_fixtures(candidate)
    return PromotionEvidence(gate_fixture(candidate, reports), reports)


def test_actual_daily_stages_then_promotes_only_with_complete_measured_evidence(
    harness, pair_store, tmp_path
):
    kwargs, counters, clock, raw = harness
    day = clock[0].date()
    prior = pair_store.load_active()
    staged = run_grounded_daily(run_date=day, **kwargs)
    assert staged.status == "STAGED" and staged.reason == "MEASURED_REPORTS_REQUIRED"
    assert counters["model"] == 80 and counters["peak"] <= 4
    assert pair_store.load_active() == prior
    output = kwargs["root"] / day.isoformat() / "batch"
    candidate = load_candidate_from_directory(output, raw)
    assert candidate.candidate_sha256 == staged.candidate_sha256
    assert len(candidate.assessments) == 80
    initial = dict(counters)
    # A complete run resumes from every persisted artifact, not a new provider call.
    assert run_grounded_daily(run_date=day, **kwargs) == staged
    assert counters == initial
    promoted = run_grounded_daily(run_date=day, evaluator=measured, **kwargs)
    assert promoted.status == "PROMOTED" and pair_store.load_active() == candidate
    assert counters == initial
    # Missing mutable status pointer after a crash is reconstructed from immutable
    # events and the actual database promotion history.
    (kwargs["root"] / day.isoformat() / "state.json").unlink()
    assert run_grounded_daily(run_date=day, **kwargs) == promoted
    assert counters == initial
    clock[0] += timedelta(days=1)
    second = run_grounded_daily(run_date=clock[0].date(), **kwargs)
    assert second.status == "STAGED" and pair_store.load_active() == candidate
    # Recollection changes retrieval provenance but v2 semantic requests reuse the
    # exact earlier model exchange for unchanged descriptions.
    assert counters["source"] > initial["source"]
    assert counters["model"] == initial["model"]
    bad = run_grounded_daily(
        run_date=clock[0].date(), evaluator=lambda _: measured(candidate), **kwargs
    )
    assert bad.status == "FAILED" and bad.reason == "MEASURED_GATE_REJECTED"
    assert pair_store.load_active() == candidate


def test_finished_batch_crash_resumes_without_repeating_model_and_failure_retains_active(
    harness, pair_store
):
    kwargs, counters, clock, _ = harness
    day = clock[0].date()
    before = pair_store.load_active()
    calls = []

    def crash_after_batch(**inputs):
        calls.append(1)
        run_batch(**inputs)
        raise RuntimeError("simulated crash after durable batch outputs")

    failed = run_grounded_daily(run_date=day, batch_runner=crash_after_batch, **kwargs)
    assert failed.status == "FAILED" and pair_store.load_active() == before
    initial = dict(counters)
    resumed = run_grounded_daily(
        run_date=day,
        batch_runner=lambda **_: (_ for _ in ()).throw(
            AssertionError("completed batch must not execute again")
        ),
        **kwargs,
    )
    assert resumed.status == "STAGED" and counters == initial and calls == [1]
    assert pair_store.load_active() == before


def test_evaluation_files_require_actual_hash_named_reports(harness, pair_store, tmp_path):
    kwargs, _, clock, raw = harness
    outcome = run_grounded_daily(run_date=clock[0].date(), **kwargs)
    candidate = load_candidate_from_directory(
        kwargs["root"] / clock[0].date().isoformat() / "batch", raw
    )
    evidence = measured(candidate)
    gate_path = tmp_path / "gate.json"
    reports_path = tmp_path / "reports"
    reports_path.mkdir()
    gate_path.write_text(evidence.gate.model_dump_json())
    assert read_promotion_evidence(gate_path, reports_path) is None
    for report in evidence.reports:
        (reports_path / (report.report_sha256 + ".json")).write_text(report.model_dump_json())
    assert read_promotion_evidence(gate_path, reports_path) == evidence
    assert outcome.status == "STAGED"


def test_seoul_schedule_worker_limit_and_legacy_branch_is_not_called(monkeypatch, harness):
    from itda.cli import run_daily_glm_refresh as cli

    before = datetime(2026, 9, 8, 22, 59, tzinfo=UTC)
    due = datetime(2026, 9, 8, 23, tzinfo=UTC)
    assert due_run_date(before) is None and next_run_at(before) == due
    assert due_run_date(due).isoformat() == "2026-09-09"
    kwargs, _, clock, _ = harness
    with pytest.raises(ValueError, match="workers"):
        run_grounded_daily(run_date=clock[0].date(), **(kwargs | {"workers": 33}))
    monkeypatch.setenv("ITDA_GROUNDED_DAILY_ENABLED", "1")
    monkeypatch.setattr(
        cli,
        "_run_grounded_scheduler",
        lambda: (_ for _ in ()).throw(RuntimeError("grounded branch reached")),
    )
    monkeypatch.setattr(
        cli,
        "_validate_authority",
        lambda: (_ for _ in ()).throw(AssertionError("legacy raw scheduler was called")),
    )
    with pytest.raises(RuntimeError, match="grounded branch reached"):
        cli.main()
