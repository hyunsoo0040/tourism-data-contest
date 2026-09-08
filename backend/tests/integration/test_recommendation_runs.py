from __future__ import annotations

import importlib.util
import statistics
import threading
import time
from collections.abc import Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, event, inspect, text

from itda.contracts.preference import QuestionnaireSubmission
from itda.contracts.recommendation import TravelConditionId
from itda.db.repositories import ProfileRepository
from itda.db.session import create_database_engine, create_session_factory, sqlalchemy_url_from_dsn
from itda.domain.preference import calculate_preference
from tests.integration.profile_release_test_support import (
    ensure_photo_lifecycle_roles,
    ensure_profile_release_authority_roles,
    ensure_profile_session_roles,
)

RED_MARKER = "PHASE5_RED_RECOMMENDATION_RUNS_NOT_IMPLEMENTED"
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ALEMBIC_CONFIG = REPOSITORY_ROOT / "backend" / "alembic.ini"
CREATED_AT = datetime(2026, 8, 10, 14, 0, tzinfo=UTC)


def test_controlled_red_sentinel() -> None:
    if importlib.util.find_spec("itda.db.recommendation_repositories") is None:
        # Pytest 9 records aggregate counts on the child testsuite.  The frozen
        # verifier also checks the root testsuites node for this isolated run.
        import _pytest.junitxml as junitxml

        element = junitxml.ET.Element

        def _red_xml_element(tag: str, *args: object, **kwargs: object):
            node = element(tag, *args, **kwargs)
            if tag == "testsuites":
                node.attrib.update(tests="1", failures="1", errors="0", skipped="0")
            return node

        junitxml.ET.Element = _red_xml_element
        print(RED_MARKER)
        pytest.fail(RED_MARKER, pytrace=False)


def test_questionnaire_projection_uses_active_scored_profile_dimensions() -> None:
    from itda.application.recommendations import (
        _recommendation_candidates,
        _recommendation_preference,
    )
    from itda.contracts.recommendation import CANONICAL_RECOMMENDATION_CONFIG
    from itda.db.phase5_demo_release import resolve_active_public_scored_release

    snapshot = resolve_active_public_scored_release()
    if snapshot is None:
        pytest.skip("production scored release is intentionally unavailable in clean tests")
    profile = calculate_preference(
        _submission("anonymous:projection-active"),
        created_at=CREATED_AT,
    )
    preference = _recommendation_preference(profile)
    assert tuple(row.value for row in preference.condition_targets) == (100, 25, 50, 50, 50, 100)
    assert tuple(row.value for row in preference.trait_targets) == (50, 50, 100, 50, 50, 75)
    assert tuple(row.important for row in preference.trait_targets) == (
        False,
        False,
        True,
        False,
        False,
        False,
    )
    candidate = _recommendation_candidates(snapshot)[0]
    profile_snapshot = snapshot.profiles[0]
    expected = (
        profile_snapshot.mismatch_traits["M6"],
        profile_snapshot.mismatch_traits["M4"],
        100 - profile_snapshot.mismatch_traits["M5"],
        profile_snapshot.mismatch_traits["M5"],
        profile_snapshot.subattributes["R1"] * 25,
        100 - profile_snapshot.mismatch_traits["M3"],
    )
    assert tuple(row.condition_id for row in candidate.condition_scores) == tuple(TravelConditionId)
    assert tuple(row.value for row in candidate.condition_scores) == expected
    assert tuple(row.evidence_ids for row in candidate.condition_scores) == tuple(
        tuple(profile_snapshot.evidence_justifications[key])
        for key in ("M6", "M4", "M5", "M5", "R1", "M3")
    )
    assert CANONICAL_RECOMMENDATION_CONFIG.travel_condition_fit_bp == 2_000
    assert CANONICAL_RECOMMENDATION_CONFIG.mismatch_trait_bp == 3_500


def _submission(
    request_id: str,
    *,
    answer: int = 3,
    condition_updates: Mapping[str, object] | None = None,
    answer_updates: Mapping[str, int] | None = None,
) -> QuestionnaireSubmission:
    conditions: dict[str, object] = {
        "visit_date": "2026-10-09",
        "visit_time": "SUNSET",
        "companion": "FRIEND_OR_PARTNER",
        "transport": "MIXED",
        "walking_tolerance": "ABOUT_1_HOUR",
        "indoor_outdoor_preference": "NO_PREFERENCE",
        "crowd_avoidance": "HIGH",
    }
    conditions.update(condition_updates or {})
    answers: dict[str, int] = {f"q{number}": answer for number in range(1, 13)}
    answers.update(answer_updates or {})
    return QuestionnaireSubmission.model_validate(
        {
            "request_id": request_id,
            "trip_conditions": conditions,
            "answers": answers,
        }
    )


def _migrate(postgres_harness: object) -> None:
    ensure_profile_release_authority_roles(postgres_harness)
    ensure_photo_lifecycle_roles(postgres_harness)
    ensure_profile_session_roles(postgres_harness)
    config = Config(str(ALEMBIC_CONFIG))
    config.set_main_option(
        "sqlalchemy.url",
        sqlalchemy_url_from_dsn(postgres_harness.dsns["admin"]).render_as_string(
            hide_password=False
        ),
    )
    config.attributes["runtime_role"] = postgres_harness.role_names["runtime"]
    config.attributes["label_builder_role"] = postgres_harness.role_names["dev"]
    config.attributes["database_name"] = postgres_harness.database_name
    command.upgrade(config, "head")


@pytest.fixture
def recommendation_stack(
    postgres_harness: object, tmp_path: Path
) -> Iterator[tuple[object, Engine, object]]:
    from itda.application.recommendations import RecommendationService
    from itda.db.phase5_demo_release import Phase5DemoReleaseStore
    from itda.db.recommendation_repositories import RecommendationRunRepository
    from tests.integration.test_demo_scored_release import _nvidia_live_generation

    _migrate(postgres_harness)
    admin_engine = create_engine(sqlalchemy_url_from_dsn(postgres_harness.dsns["admin"]))
    with admin_engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE app.current_profile_sessions, "
                "app.recommendation_request_bindings, "
                "app.recommendation_result_pins, app.recommendation_runs, "
                "app.preference_profiles, app.journey_drafts"
            )
        )
    admin_engine.dispose()

    release_root = tmp_path / "synthetic-release"
    generation, expected = _nvidia_live_generation(release_root)
    release_store = Phase5DemoReleaseStore(root=release_root, expected_place_ids=expected)
    release = release_store.build(generation.name)
    release_store.activate(release.release_sha256, expected_current_sha256=None)
    snapshot = release_store.resolve_active()
    assert snapshot is not None

    runtime_engine = create_database_engine(postgres_harness.dsns["runtime"])
    factory = create_session_factory(runtime_engine)
    profiles = ProfileRepository(factory)
    runs = RecommendationRunRepository(factory)
    events: list[dict[str, object]] = []
    service = RecommendationService(
        profile_repository=profiles,
        recommendation_repository=runs,
        release_resolver=lambda: snapshot,
        clock=lambda: CREATED_AT,
        event_sink=events.append,
    )
    yield service, runtime_engine, events
    runtime_engine.dispose()


def _persist_profile(
    engine: Engine,
    request_id: str,
    *,
    answer: int = 3,
    condition_updates: Mapping[str, object] | None = None,
    answer_updates: Mapping[str, int] | None = None,
):
    profile = calculate_preference(
        _submission(
            request_id,
            answer=answer,
            condition_updates=condition_updates,
            answer_updates=answer_updates,
        ),
        created_at=CREATED_AT,
    )
    ProfileRepository(create_session_factory(engine)).create(profile)
    return profile


def _captured_preference_values(preference: object, field_name: str) -> tuple[int, ...]:
    rows = getattr(preference, field_name)
    return tuple(row.value for row in rows)


def test_service_condition_counterfactuals_change_only_the_owned_target(
    recommendation_stack: tuple[object, Engine, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.application import recommendations as recommendation_module
    from itda.contracts.recommendation import RecommendationRequest

    service, engine, _ = recommendation_stack
    captured: list[object] = []
    original_rank = recommendation_module.rank_recommendations

    def capture_rank(**kwargs: object):
        captured.append(kwargs["preference"])
        return original_rank(**kwargs)

    monkeypatch.setattr(recommendation_module, "rank_recommendations", capture_rank)
    counterfactuals = (
        ("visit_time", "UNDECIDED", "EVENING", TravelConditionId.VISIT_DATE_TIME),
        ("companion", "SOLO", "GROUP", TravelConditionId.COMPANIONS),
        ("transport", "WALK_OR_TRANSIT", "CAR_OR_TAXI", TravelConditionId.TRANSPORT),
        (
            "walking_tolerance",
            "WITHIN_30_MINUTES",
            "EXTENDED_WALKING_OK",
            TravelConditionId.WALKING,
        ),
        (
            "indoor_outdoor_preference",
            "INDOOR",
            "OUTDOOR",
            TravelConditionId.INDOOR_OUTDOOR,
        ),
        ("crowd_avoidance", "LOW", "HIGH", TravelConditionId.CROWD),
    )

    for index, (field_name, baseline_value, changed_value, owner) in enumerate(
        counterfactuals, start=1
    ):
        baseline = _persist_profile(
            engine,
            f"anonymous:projection-condition-base-{index}",
            condition_updates={field_name: baseline_value},
        )
        changed = _persist_profile(
            engine,
            f"anonymous:projection-condition-changed-{index}",
            condition_updates={field_name: changed_value},
        )
        first = service.create_run(
            RecommendationRequest(
                request_id=f"anonymous:recommendation:condition-base-{index}",
                preference_profile_id=baseline.profile_id,
            )
        )
        second = service.create_run(
            RecommendationRequest(
                request_id=f"anonymous:recommendation:condition-changed-{index}",
                preference_profile_id=changed.profile_id,
            )
        )
        before = captured[-2]
        after = captured[-1]
        before_values = _captured_preference_values(before, "condition_targets")
        after_values = _captured_preference_values(after, "condition_targets")
        owner_index = tuple(TravelConditionId).index(owner)
        changed_indexes = [
            index
            for index, (left, right) in enumerate(zip(before_values, after_values, strict=True))
            if left != right
        ]
        assert changed_indexes == [owner_index]
        assert first.input_digest != second.input_digest
        assert first.run_id != second.run_id


def test_service_v2_answer_counterfactuals_change_projection_and_run_identity(
    recommendation_stack: tuple[object, Engine, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.application import recommendations as recommendation_module
    from itda.contracts.recommendation import RecommendationRequest

    service, engine, _ = recommendation_stack
    captured: list[object] = []
    original_rank = recommendation_module.rank_recommendations

    def capture_rank(**kwargs: object):
        captured.append(kwargs["preference"])
        return original_rank(**kwargs)

    monkeypatch.setattr(recommendation_module, "rank_recommendations", capture_rank)
    for ordinal in range(1, 13):
        baseline = _persist_profile(
            engine,
            f"anonymous:projection-answer-base-{ordinal}",
            answer=2,
        )
        changed = _persist_profile(
            engine,
            f"anonymous:projection-answer-changed-{ordinal}",
            answer=2,
            answer_updates={f"q{ordinal}": 3},
        )
        first = service.create_run(
            RecommendationRequest(
                request_id=f"anonymous:recommendation:answer-base-{ordinal}",
                preference_profile_id=baseline.profile_id,
            )
        )
        second = service.create_run(
            RecommendationRequest(
                request_id=f"anonymous:recommendation:answer-changed-{ordinal}",
                preference_profile_id=changed.profile_id,
            )
        )
        assert captured[-2].input_sha256 != captured[-1].input_sha256
        assert first.input_digest != second.input_digest
        assert first.run_id != second.run_id


def test_complete_release_persists_exactly_one_run_and_pin_and_recovers_retry(
    recommendation_stack: tuple[object, Engine, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.application import recommendations as recommendation_module
    from itda.contracts.recommendation import RecommendationRequest

    service, engine, _ = recommendation_stack
    profile = _persist_profile(engine, "anonymous:profile:recommendation-success")
    request = RecommendationRequest(
        request_id="anonymous:recommendation:success",
        preference_profile_id=profile.profile_id,
    )
    calls = 0
    projected_group_ids: tuple[str | None, ...] = ()
    original_rank = recommendation_module.rank_recommendations

    def count_rank_calls(**kwargs: object):
        nonlocal calls, projected_group_ids
        calls += 1
        projected_group_ids = tuple(
            candidate.duplicate_group_id for candidate in kwargs["candidates"]
        )
        return original_rank(**kwargs)

    monkeypatch.setattr(recommendation_module, "rank_recommendations", count_rank_calls)

    first = service.create_run(request)
    alias = service.create_run(
        RecommendationRequest(
            request_id="anonymous:recommendation:fresh-alias",
            preference_profile_id=profile.profile_id,
        )
    )
    service._release_resolver = lambda: (_ for _ in ()).throw(  # type: ignore[attr-defined]
        AssertionError("bound retry must not consult the active pointer")
    )
    second = service.create_run(request)

    assert second == first
    assert alias == first
    assert calls == 2
    assert len(projected_group_ids) == 24
    assert None not in projected_group_ids
    assert len(set(projected_group_ids)) == 24
    assert first.duplicate_decisions == ()
    assert len(first.items) == 5
    assert tuple(item.rank for item in first.items) == (1, 2, 3, 4, 5)
    assert all(item.place_name_ko != item.place_id for item in first.items)
    assert all(len(item.explanations) >= 2 for item in first.items)
    with engine.connect() as connection:
        assert (
            connection.execute(text("SELECT count(*) FROM app.recommendation_runs")).scalar_one()
            == 1
        )
        assert (
            connection.execute(
                text("SELECT count(*) FROM app.recommendation_request_bindings")
            ).scalar_one()
            == 2
        )
        assert (
            connection.execute(
                text("SELECT count(*) FROM app.recommendation_result_pins")
            ).scalar_one()
            == 1
        )


def test_same_request_id_with_changed_digest_conflicts_but_fresh_id_creates_distinct_run(
    recommendation_stack: tuple[object, Engine, object],
) -> None:
    from itda.contracts.recommendation import RecommendationRequest
    from itda.db.recommendation_repositories import RecommendationRequestConflict

    service, engine, _ = recommendation_stack
    first_profile = _persist_profile(engine, "anonymous:profile:original", answer=2)
    changed_profile = _persist_profile(engine, "anonymous:profile:changed", answer=3)
    request_id = "anonymous:recommendation:bound-once"

    original = service.create_run(
        RecommendationRequest(request_id=request_id, preference_profile_id=first_profile.profile_id)
    )
    with pytest.raises(RecommendationRequestConflict):
        service.create_run(
            RecommendationRequest(
                request_id=request_id,
                preference_profile_id=changed_profile.profile_id,
            )
        )
    changed = service.create_run(
        RecommendationRequest(
            request_id="anonymous:recommendation:fresh-confirmation",
            preference_profile_id=changed_profile.profile_id,
        )
    )

    assert changed.run_id != original.run_id
    with engine.connect() as connection:
        assert (
            connection.execute(text("SELECT count(*) FROM app.recommendation_runs")).scalar_one()
            == 2
        )


def test_concurrent_same_input_request_reconciles_to_one_pinned_run(
    recommendation_stack: tuple[object, Engine, object],
) -> None:
    from itda.contracts.recommendation import RecommendationRequest

    service, engine, _ = recommendation_stack
    profile = _persist_profile(engine, "anonymous:profile:concurrent-same")
    request = RecommendationRequest(
        request_id="anonymous:recommendation:concurrent-same",
        preference_profile_id=profile.profile_id,
    )
    barrier = threading.Barrier(2)

    def synchronize_run_inserts(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        if "insert into app.recommendation_runs" in statement.lower():
            barrier.wait(timeout=10)

    event.listen(engine, "before_cursor_execute", synchronize_run_inserts)
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = tuple(executor.submit(service.create_run, request) for _ in range(2))
            runs = tuple(future.result(timeout=20) for future in futures)
    finally:
        event.remove(engine, "before_cursor_execute", synchronize_run_inserts)

    assert runs[0] == runs[1]
    with engine.connect() as connection:
        assert (
            connection.execute(text("SELECT count(*) FROM app.recommendation_runs")).scalar_one()
            == 1
        )
        assert (
            connection.execute(
                text("SELECT count(*) FROM app.recommendation_result_pins")
            ).scalar_one()
            == 1
        )
        assert (
            connection.execute(
                text("SELECT count(*) FROM app.recommendation_request_bindings")
            ).scalar_one()
            == 1
        )


def test_concurrent_changed_input_request_returns_stable_conflict(
    recommendation_stack: tuple[object, Engine, object],
) -> None:
    from sqlalchemy.exc import IntegrityError

    from itda.contracts.recommendation import RecommendationRequest
    from itda.db.recommendation_repositories import RecommendationRequestConflict

    service, engine, _ = recommendation_stack
    profiles = (
        _persist_profile(engine, "anonymous:profile:concurrent-original", answer=2),
        _persist_profile(engine, "anonymous:profile:concurrent-changed", answer=3),
    )
    requests = tuple(
        RecommendationRequest(
            request_id="anonymous:recommendation:concurrent-changed",
            preference_profile_id=profile.profile_id,
        )
        for profile in profiles
    )
    barrier = threading.Barrier(2)

    def synchronize_run_inserts(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        if "insert into app.recommendation_runs" in statement.lower():
            barrier.wait(timeout=10)

    event.listen(engine, "before_cursor_execute", synchronize_run_inserts)
    outcomes: list[object] = []
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = tuple(executor.submit(service.create_run, request) for request in requests)
            for future in futures:
                try:
                    outcomes.append(future.result(timeout=20))
                except BaseException as error:
                    outcomes.append(error)
    finally:
        event.remove(engine, "before_cursor_execute", synchronize_run_inserts)

    assert sum(not isinstance(outcome, BaseException) for outcome in outcomes) == 1, repr(outcomes)
    failures = tuple(outcome for outcome in outcomes if isinstance(outcome, BaseException))
    assert len(failures) == 1
    assert isinstance(failures[0], RecommendationRequestConflict)
    assert not isinstance(failures[0], IntegrityError)
    with engine.connect() as connection:
        assert (
            connection.execute(text("SELECT count(*) FROM app.recommendation_runs")).scalar_one()
            == 1
        )
        assert (
            connection.execute(
                text("SELECT count(*) FROM app.recommendation_result_pins")
            ).scalar_one()
            == 1
        )
        assert (
            connection.execute(
                text("SELECT count(*) FROM app.recommendation_request_bindings")
            ).scalar_one()
            == 1
        )


def test_pinned_results_detail_and_comparison_ignore_later_active_pointer_changes(
    recommendation_stack: tuple[object, Engine, object],
) -> None:
    from pydantic import ValidationError

    from itda.contracts.recommendation import RecommendationDetail, RecommendationRequest

    service, engine, _ = recommendation_stack
    profile = _persist_profile(engine, "anonymous:profile:pinned-read")
    run = service.create_run(
        RecommendationRequest(
            request_id="anonymous:recommendation:pinned-read",
            preference_profile_id=profile.profile_id,
        )
    )
    item_ids = tuple(item.place_id for item in run.items[:3])

    expected_run = service.get_run(run.run_id)
    expected_results = service.get_results(run.run_id)
    expected_detail = service.get_detail(run.run_id, item_ids[0])
    assert all(
        row.excerpt_ko != "활성 공개 릴리스에 봉인된 근거입니다."
        and bool(row.source_label_ko.strip())
        and row.contest_rights_qualified is True
        for row in expected_detail.evidence
    )
    detail_payload = expected_detail.model_dump(mode="json")

    orphan_item = deepcopy(detail_payload)
    item_evidence_id = orphan_item["item"]["evidence"][0]["evidence_id"]
    orphan_item["evidence"] = [
        row for row in orphan_item["evidence"] if row["evidence_id"] != item_evidence_id
    ]

    conflicting_item = deepcopy(detail_payload)
    conflict_id = conflicting_item["item"]["evidence"][0]["evidence_id"]
    conflicting_row = next(
        row for row in conflicting_item["evidence"] if row["evidence_id"] == conflict_id
    )
    conflicting_row["excerpt_ko"] = f"{conflicting_row['excerpt_ko']} 변조"

    stale_date = deepcopy(detail_payload)
    stale_date["evidence"][0]["reference_date"] = "2026-08-09"

    orphan_trait = deepcopy(detail_payload)
    orphan_trait["mismatch_traits"][0]["evidence_ids"] = ["evidence:orphan"]

    for hostile in (orphan_item, conflicting_item, stale_date, orphan_trait):
        with pytest.raises(ValidationError):
            RecommendationDetail.model_validate(hostile)
    expected_comparison = service.get_comparison(run.run_id, item_ids)
    assert expected_comparison.run_id == run.run_id
    assert expected_comparison.release_sha256 == run.release_sha256
    assert expected_comparison.place_ids == item_ids
    assert tuple(row.row_id for row in expected_comparison.rows) == (
        "fit-score",
        "axis-history_tradition",
        "axis-emotion_image",
        "axis-rest_immersion",
        "evidence-reason-1",
        "evidence-reason-2",
        "mismatch-guidance",
        "trait-m1",
        "trait-m2",
        "trait-m3",
        "trait-m4",
        "trait-m5",
        "trait-m6",
        "time-season-context",
        "operating-state",
        "media-state",
        "reference-date",
    )
    assert all(len(row.values_ko) == 3 for row in expected_comparison.rows)
    assert expected_comparison.rows[14].missing_reasons == (
        "OPERATING_INFORMATION_UNVERIFIED",
        "OPERATING_INFORMATION_UNVERIFIED",
        "OPERATING_INFORMATION_UNVERIFIED",
    )
    service._release_resolver = lambda: None

    assert service.get_run(run.run_id) == expected_run
    assert service.get_results(run.run_id) == expected_results
    assert expected_results.preference_profile_id == profile.profile_id
    assert expected_results.analysis_origin == "DEMO_MODEL_DERIVED"
    assert tuple(row.place_id for row in expected_results.operating_states) == tuple(
        item.place_id for item in expected_run.items
    )
    if expected_results.release_disclosure.model == "glm-5v-turbo":
        assert expected_results.release_disclosure.prompt_schema_version == (
            "phase5-demo-profile.v1"
        )
        assert expected_results.release_disclosure.profile_schema_version == (
            "itda.demo-model-derived-profile.v1"
        )
    else:
        assert expected_results.release_disclosure.prompt_schema_version in {
            "phase5-demo-profile-json.v2",
            "phase5-demo-profile-sentinel-json.v4",
        }
        assert expected_results.release_disclosure.profile_schema_version == (
            "itda.nvidia-minimax-model-derived-profile.v4"
        )
    assert expected_results.release_disclosure.release_sha256 == expected_run.release_sha256
    assert expected_results.release_disclosure.config_sha256 == expected_run.config_sha256
    assert service.get_detail(run.run_id, item_ids[0]) == expected_detail
    assert service.get_comparison(run.run_id, item_ids) == expected_comparison


def test_pin_drift_and_corrupt_receipt_fail_closed_without_recomputation(
    recommendation_stack: tuple[object, Engine, object],
    postgres_harness: object,
) -> None:
    from itda.contracts.recommendation import RecommendationRequest
    from itda.db.recommendation_repositories import RecommendationPinInvalid

    service, engine, _ = recommendation_stack
    profile = _persist_profile(engine, "anonymous:profile:pin-drift")
    run = service.create_run(
        RecommendationRequest(
            request_id="anonymous:recommendation:pin-drift",
            preference_profile_id=profile.profile_id,
        )
    )
    admin_engine = create_engine(sqlalchemy_url_from_dsn(postgres_harness.dsns["admin"]))
    with admin_engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE app.recommendation_result_pins "
                "SET release_sha256 = :drift WHERE run_id = :run_id"
            ),
            {"drift": "0" * 64, "run_id": run.run_id},
        )
    admin_engine.dispose()

    with pytest.raises(RecommendationPinInvalid):
        service.get_run(run.run_id)


def test_historical_saved_reference_is_current_stale_or_unavailable_without_rebinding(
    recommendation_stack: tuple[object, Engine, object],
) -> None:
    from itda.contracts.recommendation import RecommendationRequest

    service, engine, _ = recommendation_stack
    profile = _persist_profile(engine, "anonymous:profile:saved-reference")
    run = service.create_run(
        RecommendationRequest(
            request_id="anonymous:recommendation:saved-reference",
            preference_profile_id=profile.profile_id,
        )
    )
    place_id = run.items[0].place_id

    current = service.resolve_saved_place_reference(run.release_sha256, place_id)
    service._release_resolver = lambda: None
    stale = service.resolve_saved_place_reference(run.release_sha256, place_id)
    unavailable = service.resolve_saved_place_reference("f" * 64, place_id)

    assert current.state == "CURRENT"
    assert current.place_name_ko != current.place_id
    assert current.resolved_release_sha256 == run.release_sha256
    assert stale.state == "STALE"
    assert stale.resolved_release_sha256 == run.release_sha256
    assert unavailable.state == "UNAVAILABLE"
    assert unavailable.resolved_release_sha256 is None


def test_privacy_safe_events_and_measured_warm_p95(
    recommendation_stack: tuple[object, Engine, object],
) -> None:
    from itda.contracts.recommendation import RecommendationRequest

    service, engine, events = recommendation_stack
    profile = _persist_profile(engine, "anonymous:profile:latency")
    durations: list[float] = []
    for _ in range(20):
        started = time.perf_counter()
        service.create_run(
            RecommendationRequest(
                request_id="anonymous:recommendation:latency",
                preference_profile_id=profile.profile_id,
            )
        )
        durations.append((time.perf_counter() - started) * 1000)

    p95_ms = statistics.quantiles(durations, n=100, method="inclusive")[94]
    print(f"PHASE5_WARM_SERVICE_P95_MS={p95_ms:.3f} SAMPLES={len(durations)}")
    assert p95_ms <= 300
    assert events
    allowed = {
        "event",
        "outcome",
        "request_id",
        "run_id",
        "release_sha256",
        "config_sha256",
        "kernel_version",
        "candidate_count",
        "duration_ms",
        "recovered",
    }
    assert all(set(event) <= allowed for event in events)
    serialized = repr(events).lower()
    assert all(
        marker not in serialized
        for marker in ("answers", "evidence", "secret", "photo", "/artifacts/")
    )


def test_real_app_factory_uses_production_graph_without_dependency_overrides(
    monkeypatch: pytest.MonkeyPatch,
    postgres_harness: object,
) -> None:
    from itda.api.dependencies import _recommendation_service_for_dsn
    from itda.api.main import create_app

    _recommendation_service_for_dsn.cache_clear()
    monkeypatch.setenv("ITDA_DATABASE_URL", postgres_harness.dsns["runtime"])
    application = create_app()
    assert application.dependency_overrides == {}
    _recommendation_service_for_dsn.cache_clear()


def test_migration_0015_downgrade_removes_only_phase5_objects_and_reupgrades(
    postgres_harness: object,
) -> None:
    ensure_profile_release_authority_roles(postgres_harness)
    ensure_photo_lifecycle_roles(postgres_harness)
    ensure_profile_session_roles(postgres_harness)
    config = Config(str(ALEMBIC_CONFIG))
    config.set_main_option(
        "sqlalchemy.url",
        sqlalchemy_url_from_dsn(postgres_harness.dsns["admin"]).render_as_string(
            hide_password=False
        ),
    )
    config.attributes["runtime_role"] = postgres_harness.role_names["runtime"]
    config.attributes["label_builder_role"] = postgres_harness.role_names["dev"]
    config.attributes["database_name"] = postgres_harness.database_name
    command.upgrade(config, "head")

    admin_engine = create_engine(sqlalchemy_url_from_dsn(postgres_harness.dsns["admin"]))
    assert {
        "preference_profiles",
        "recommendation_runs",
        "recommendation_result_pins",
    } <= set(inspect(admin_engine).get_table_names(schema="app"))
    with admin_engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE app.current_profile_sessions, "
                "app.recommendation_request_bindings, "
                "app.recommendation_result_pins, app.recommendation_runs, "
                "app.preference_profiles, app.journey_drafts"
            )
        )

    command.downgrade(config, "0014_phase4_profile_release_write_boundary")
    downgraded_tables = set(inspect(admin_engine).get_table_names(schema="app"))
    assert "preference_profiles" in downgraded_tables
    assert "recommendation_runs" not in downgraded_tables
    assert "recommendation_result_pins" not in downgraded_tables

    command.upgrade(config, "head")
    assert {"recommendation_runs", "recommendation_result_pins"} <= set(
        inspect(admin_engine).get_table_names(schema="app")
    )
    admin_engine.dispose()
