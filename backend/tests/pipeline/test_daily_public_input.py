from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from itda.collectors.base import CollectedResponse, CollectionError, RequestPolicy
from itda.contracts.mvp_daily_refresh import DAILY_REFRESH_AUTHORITY_V2
from itda.contracts.mvp_place_scoring import SCORING_DIMENSIONS, PublicScoringRequest
from itda.contracts.mvp_public_catalog import (
    PublicEvidenceInventory,
    PublicPlaceCatalog,
    PublicPlaceRelations,
)
from itda.contracts.mvp_scored_release import MvpScoredRelease
from itda.db.mvp_release_overlay import ActiveReleaseOverlayResolver, DailyRefreshStoreError
from itda.domain.canonical import canonical_sha256
from itda.operating.service import ProviderPlace
from itda.pipeline.daily_incremental_scoring import (
    DailyTerminalScoringError,
    daily_evidence_inventory_sha256,
    execute_incremental_scoring,
)
from itda.pipeline.daily_public_input import (
    DailyCollectionIncomplete,
    LiveDailyTourApiProvider,
    build_daily_delta,
    build_incremental_scoring_plan,
    collect_daily_snapshot,
)
from itda.pipeline.daily_scored_release import materialize_daily_scored_release
from itda.pipeline.mvp_place_scoring import MvpScoringError, ScoringAttemptEvent

REPO_ROOT = Path(__file__).resolve().parents[3]
CATALOG_PATH = REPO_ROOT / "artifacts/public/catalog/public-place-catalog-v1.json"
EVIDENCE_PATH = REPO_ROOT / "artifacts/public/catalog/public-evidence-inventory-v1.json"
RELATIONS_PATH = REPO_ROOT / "artifacts/public/catalog/public-place-relations-v1.json"
RELEASE_ROOT = REPO_ROOT / "artifacts/public/catalog/mvp-scored-releases/releases"
COLLECTED_AT = datetime(2026, 9, 6, 0, 0, tzinfo=UTC)


class SyntheticDailyProvider:
    def __init__(
        self,
        *,
        metadata_version: str = "1",
        changed_content_id: str | None = None,
        fail_content_id: str | None = None,
    ) -> None:
        self.metadata_version = metadata_version
        self.changed_content_id = changed_content_id
        self.fail_content_id = fail_content_id
        self.common_calls: list[ProviderPlace] = []
        self.intro_calls: list[ProviderPlace] = []
        self.closed = False

    def fetch_common(self, place: ProviderPlace) -> CollectedResponse:
        self.common_calls.append(place)
        overview = f"{place.content_id} 공개 소개"
        if place.content_id == self.changed_content_id:
            overview += " 변경"
        payload = {
            "response": {
                "header": {"resultCode": "0000"},
                "body": {
                    "totalCount": 1,
                    "items": {
                        "item": {
                            "contentid": place.content_id,
                            "contenttypeid": place.content_type_id,
                            "title": f"공개 장소 {place.content_id}",
                            "addr1": "경상북도 경주시 합성로 1",
                            "mapx": "129.2",
                            "mapy": "35.8",
                            "overview": overview,
                            "cat1": "A01",
                            "cat2": "A0101",
                            "cat3": "A01010100",
                        }
                    },
                },
            }
        }
        return self._response("detailCommon2", payload)

    def fetch_intro(self, place: ProviderPlace) -> CollectedResponse:
        self.intro_calls.append(place)
        if place.content_id == self.fail_content_id:
            raise RuntimeError("synthetic collection failure")
        payload = {
            "response": {
                "header": {"resultCode": "0000"},
                "body": {
                    "totalCount": 1,
                    "items": {
                        "item": {
                            "contentid": place.content_id,
                            "usetime": "09:00~18:00",
                            "usetimeculture": "09:00~18:00",
                            "playtime": "10:00~17:00",
                            "usetimeleports": "09:00~18:00",
                            "checkintime": "15:00",
                            "opentime": "09:00~18:00",
                            "opentimefood": "09:00~18:00",
                        }
                    },
                },
            }
        }
        return self._response("detailIntro2", payload)

    def close(self) -> None:
        self.closed = True

    def _response(self, operation: str, payload: object) -> CollectedResponse:
        provenance = {
            "metadata_version": self.metadata_version,
            "operation": operation,
            "payload": payload,
        }
        return CollectedResponse(
            provider="TOUR_API",
            endpoint=operation,
            request_scope={},
            retrieved_at=COLLECTED_AT,
            http_status=200,
            raw_response_sha256=canonical_sha256(provenance),
            raw_body_base64="",
            modifiedtime=f"2026090600000{self.metadata_version}",
            rights=(),
            payload=payload,
        )


@pytest.mark.parametrize("content_type_id", ("12", "14", "15", "28", "32", "38", "39"))
def test_daily_provider_uses_current_operation_parameters(
    monkeypatch: pytest.MonkeyPatch,
    content_type_id: str,
) -> None:
    place = ProviderPlace(content_id="synthetic-content-id", content_type_id=content_type_id)
    responses = SyntheticDailyProvider()
    common_response = responses.fetch_common(place)
    intro_response = responses.fetch_intro(place)
    calls: list[tuple[str, dict[str, str], bool]] = []
    policies: list[RequestPolicy] = []
    closed = False

    class SyntheticClient:
        def __init__(self, *, service_key: str, policy: RequestPolicy) -> None:
            del service_key
            policies.append(policy)

        def request(
            self,
            operation: str,
            parameters: dict[str, str],
            *,
            explicit_opt_in: bool,
        ) -> CollectedResponse:
            calls.append((operation, dict(parameters), explicit_opt_in))
            return common_response if operation == "detailCommon2" else intro_response

        def close(self) -> None:
            nonlocal closed
            closed = True

    monkeypatch.setattr("itda.pipeline.daily_public_input.KorService2Client", SyntheticClient)
    provider = LiveDailyTourApiProvider(service_key="synthetic-unused-key", timeout_seconds=7.0)
    try:
        assert provider.fetch_common(place) is common_response
        assert provider.fetch_intro(place) is intro_response
    finally:
        provider.close()

    assert calls == [
        (
            "detailCommon2",
            {"contentId": place.content_id, "numOfRows": "1", "pageNo": "1"},
            True,
        ),
        (
            "detailIntro2",
            {
                "contentId": place.content_id,
                "contentTypeId": content_type_id,
                "numOfRows": "1",
                "pageNo": "1",
            },
            True,
        ),
    ]
    assert len(policies) == 1
    assert policies[0].max_attempts == 1
    assert policies[0].timeout_seconds == 7.0
    assert policies[0].initial_backoff_seconds == 0
    assert closed is True


def _artifacts() -> tuple[PublicPlaceCatalog, PublicEvidenceInventory]:
    return (
        PublicPlaceCatalog.model_validate_json(CATALOG_PATH.read_bytes()),
        PublicEvidenceInventory.model_validate_json(EVIDENCE_PATH.read_bytes()),
    )


def _snapshot(
    provider: SyntheticDailyProvider,
    *,
    run_date: date,
    previous_snapshot_sha256: str | None = None,
):
    catalog, evidence = _artifacts()
    return collect_daily_snapshot(
        catalog=catalog,
        evidence_inventory=evidence,
        provider=provider,
        run_date=run_date,
        collected_at=COLLECTED_AT,
        previous_snapshot_sha256=previous_snapshot_sha256,
    )


def test_real_public_100_collects_complete_canonical_semantic_snapshot() -> None:
    provider = SyntheticDailyProvider()

    snapshot = _snapshot(provider, run_date=date(2026, 9, 6))

    assert len(snapshot.places) == 100
    assert tuple(row.place_id for row in snapshot.places) == tuple(
        sorted(row.place_id for row in snapshot.places)
    )
    assert len(provider.common_calls) == 100
    assert len(provider.intro_calls) == 100
    assert snapshot.authority_sha256 == DAILY_REFRESH_AUTHORITY_V2.authority_sha256
    assert all(
        row.request.place.category.endswith("(A01/A0101/A01010100)") for row in snapshot.places
    )
    assert all(row.request.evidence[0].excerpt == row.evidence.excerpt for row in snapshot.places)


def test_metadata_only_changes_do_not_schedule_glm_scoring() -> None:
    previous = _snapshot(
        SyntheticDailyProvider(metadata_version="1"),
        run_date=date(2026, 9, 5),
    )
    current = _snapshot(
        SyntheticDailyProvider(metadata_version="2"),
        run_date=date(2026, 9, 6),
        previous_snapshot_sha256=previous.snapshot_sha256,
    )

    delta = build_daily_delta(previous, current)

    assert delta.changed_place_ids == ()
    assert len(delta.unchanged_place_ids) == 100
    assert previous.snapshot_sha256 != current.snapshot_sha256
    assert previous.places[0].row_sha256 != current.places[0].row_sha256
    assert previous.places[0].request.request_sha256 == current.places[0].request.request_sha256
    with pytest.raises(ValueError, match="non-empty matching delta"):
        build_incremental_scoring_plan(snapshot=current, delta=delta)


def test_semantic_change_schedules_only_changed_place() -> None:
    catalog, _ = _artifacts()
    target_content_id = next(
        crosswalk.source_id
        for crosswalk in catalog.places[0].provider_crosswalk
        if crosswalk.provider == "TOUR_API"
    )
    target_place_id = catalog.places[0].place_id
    previous = _snapshot(SyntheticDailyProvider(), run_date=date(2026, 9, 5))
    current = _snapshot(
        SyntheticDailyProvider(changed_content_id=target_content_id),
        run_date=date(2026, 9, 6),
        previous_snapshot_sha256=previous.snapshot_sha256,
    )

    delta = build_daily_delta(previous, current)
    plan = build_incremental_scoring_plan(snapshot=current, delta=delta)

    assert delta.changed_place_ids == (target_place_id,)
    assert len(delta.unchanged_place_ids) == 99
    assert plan.scoring_place_ids == (target_place_id,)
    assert plan.first_pass_count == 1
    current_target = next(row for row in current.places if row.place_id == target_place_id)
    assert plan.request_sha256 == (current_target.request.request_sha256,)
    assert plan.maximum_calls == 200
    assert plan.retry_limit_per_place == 1
    assert plan.concurrency == 1
    assert plan.fallback is False
    assert plan.pay_as_you_go_fallback is False


def test_one_failed_provider_response_rejects_entire_snapshot() -> None:
    catalog, _ = _artifacts()
    target = catalog.places[0]
    target_content_id = next(
        crosswalk.source_id
        for crosswalk in target.provider_crosswalk
        if crosswalk.provider == "TOUR_API"
    )
    provider = SyntheticDailyProvider(fail_content_id=target_content_id)

    with pytest.raises(
        DailyCollectionIncomplete,
        match="TOUR_API_COLLECTION_FAILED",
    ) as raised:
        _snapshot(provider, run_date=date(2026, 9, 6))

    assert raised.value.safe_reason == "TOUR_API_COLLECTION_FAILED"
    assert raised.value.failure is not None
    assert raised.value.failure.model_dump(mode="json") == {
        "schema_version": "mvp-daily-collection-failure.v1",
        "place_id": target.place_id,
        "operation": "detailIntro2",
        "failure_category": "PROVIDER_TRANSPORT",
        "failure_code": "UNEXPECTED_PROVIDER_ERROR",
    }


@pytest.mark.parametrize(
    ("response_shape", "failure_code"),
    (
        ("empty_string", "CONTENT_ITEMS_MISSING"),
        ("empty_object", "CONTENT_ITEMS_MISSING"),
        ("empty_list", "CONTENT_ITEMS_MISSING"),
        ("wrong_id", "CONTENT_ID_MISMATCH"),
        ("missing_id", "CONTENT_ID_MISMATCH"),
        ("duplicate_id", "CONTENT_ID_DUPLICATED"),
    ),
)
def test_common_response_identity_failures_remain_fail_closed(
    response_shape: str,
    failure_code: str,
) -> None:
    class InvalidCommonProvider(SyntheticDailyProvider):
        def fetch_common(self, place: ProviderPlace) -> CollectedResponse:
            self.common_calls.append(place)
            item = {"contentid": place.content_id, "title": "synthetic-private-body"}
            shapes: dict[str, object] = {
                "empty_string": "",
                "empty_object": {},
                "empty_list": {"item": []},
                "wrong_id": {"item": {**item, "contentid": "different-content-id"}},
                "missing_id": {"item": {"title": "synthetic-private-body"}},
                "duplicate_id": {"item": [item, item]},
            }
            return self._response(
                "detailCommon2",
                {
                    "response": {
                        "header": {"resultCode": "0000", "resultMsg": "OK"},
                        "body": {"items": shapes[response_shape]},
                    }
                },
            )

    provider = InvalidCommonProvider()
    catalog, _ = _artifacts()
    with pytest.raises(DailyCollectionIncomplete) as raised:
        _snapshot(provider, run_date=date(2026, 9, 6))

    assert raised.value.safe_reason == "TOUR_API_COLLECTION_FAILED"
    failure = raised.value.failure
    assert failure is not None
    assert failure.place_id == catalog.places[0].place_id
    assert failure.operation == "detailCommon2"
    assert failure.failure_category == "RESPONSE_VALIDATION"
    assert failure.failure_code == failure_code
    assert len(provider.common_calls) == 1
    assert len(provider.intro_calls) == 0
    assert "synthetic-private-body" not in failure.model_dump_json()
    assert "different-content-id" not in failure.model_dump_json()


def test_collection_error_exposes_only_normalized_failure_fields() -> None:
    class FailingProvider(SyntheticDailyProvider):
        def fetch_common(self, place: ProviderPlace) -> CollectedResponse:
            raise CollectionError(
                "private upstream response",
                outcome="provider_rejected",
                category="http response",
                normalized_failure_reason="provider unavailable",
                raw_body_sha256="f" * 64,
            )

    catalog, _ = _artifacts()
    with pytest.raises(DailyCollectionIncomplete) as raised:
        _snapshot(FailingProvider(), run_date=date(2026, 9, 6))

    failure = raised.value.failure
    assert failure is not None
    payload = failure.model_dump(mode="json")
    assert payload["operation"] == "detailCommon2"
    assert payload["failure_category"] == "HTTP_RESPONSE"
    assert payload["failure_code"] == "PROVIDER_UNAVAILABLE"
    serialized = json.dumps(payload)
    assert "private upstream response" not in serialized
    assert "raw_body" not in serialized
    assert "ffffffff" not in serialized


class SyntheticScoringTransport:
    def __init__(
        self,
        *,
        fail_until: dict[str, int] | None = None,
        terminal_reason: str | None = None,
    ) -> None:
        self.fail_until = fail_until or {}
        self.terminal_reason = terminal_reason
        self.calls: Counter[str] = Counter()

    def score(
        self,
        request: PublicScoringRequest,
        *,
        timeout_seconds: int,
        max_tokens: int,
    ) -> bytes:
        del timeout_seconds, max_tokens
        place_id = request.place.place_id
        self.calls[place_id] += 1
        if self.terminal_reason is not None:
            raise MvpScoringError(self.terminal_reason)
        if self.calls[place_id] <= self.fail_until.get(place_id, 0):
            raise MvpScoringError("GLM_TIMEOUT")
        evidence_id = request.evidence[0].evidence_id
        return json.dumps(
            {
                "H": 50,
                "E": 51,
                "R": 52,
                **{dimension: 2 for dimension in SCORING_DIMENSIONS[3:15]},
                **{dimension: 50 for dimension in SCORING_DIMENSIONS[15:]},
                "confidence": 60,
                "justifications": {
                    dimension: {
                        "evidence_ids": [evidence_id],
                        "justification_ko": f"{dimension} 합성 공개 근거",
                    }
                    for dimension in SCORING_DIMENSIONS
                },
            },
            ensure_ascii=False,
        ).encode()

    def close(self) -> None:
        pass


def _one_change_execution_inputs():
    catalog, _ = _artifacts()
    target_content_id = next(
        crosswalk.source_id
        for crosswalk in catalog.places[0].provider_crosswalk
        if crosswalk.provider == "TOUR_API"
    )
    previous = _snapshot(SyntheticDailyProvider(), run_date=date(2026, 9, 5))
    current = _snapshot(
        SyntheticDailyProvider(changed_content_id=target_content_id),
        run_date=date(2026, 9, 6),
        previous_snapshot_sha256=previous.snapshot_sha256,
    )
    return (
        catalog,
        current,
        build_incremental_scoring_plan(
            snapshot=current,
            delta=build_daily_delta(previous, current),
        ),
    )


def test_incremental_executor_reserves_before_transport_and_retries_once() -> None:
    catalog, snapshot, plan = _one_change_execution_inputs()
    place_id = plan.scoring_place_ids[0]
    transport = SyntheticScoringTransport(fail_until={place_id: 1})
    reserved: list[ScoringAttemptEvent] = []
    completed: list[ScoringAttemptEvent] = []

    outcome = execute_incremental_scoring(
        snapshot=snapshot,
        plan=plan,
        transport=transport,
        catalog_sha256=catalog.catalog_sha256,
        reserve_call=lambda event: reserved.append(event),
        on_attempt=lambda event: completed.append(event),
    )

    assert transport.calls == Counter({place_id: 2})
    assert [row.attempt_number for row in reserved] == [1, 2]
    assert [row.status for row in reserved] == ["STARTED", "STARTED"]
    assert [row.status for row in completed] == ["FAILED", "SUCCEEDED"]
    assert outcome.call_count == 2
    assert tuple(outcome.results) == (place_id,)
    assert outcome.failed == {}
    assert outcome.results[place_id].evidence_inventory_sha256 == (
        daily_evidence_inventory_sha256(snapshot)
    )


def test_incremental_executor_does_not_call_provider_when_reservation_fails() -> None:
    catalog, snapshot, plan = _one_change_execution_inputs()
    transport = SyntheticScoringTransport()

    def reject_reservation(event: ScoringAttemptEvent) -> None:
        del event
        raise RuntimeError("synthetic reservation failure")

    with pytest.raises(RuntimeError, match="reservation failure"):
        execute_incremental_scoring(
            snapshot=snapshot,
            plan=plan,
            transport=transport,
            catalog_sha256=catalog.catalog_sha256,
            reserve_call=reject_reservation,
        )

    assert transport.calls == Counter()


def test_incremental_executor_stops_immediately_on_terminal_provider_error() -> None:
    catalog, snapshot, plan = _one_change_execution_inputs()
    transport = SyntheticScoringTransport(terminal_reason="GLM_HTTP_AUTH_REJECTED")
    reserved: list[ScoringAttemptEvent] = []
    completed: list[ScoringAttemptEvent] = []

    with pytest.raises(DailyTerminalScoringError, match="GLM_HTTP_AUTH_REJECTED"):
        execute_incremental_scoring(
            snapshot=snapshot,
            plan=plan,
            transport=transport,
            catalog_sha256=catalog.catalog_sha256,
            reserve_call=lambda event: reserved.append(event),
            on_attempt=lambda event: completed.append(event),
        )

    assert len(reserved) == 1
    assert len(completed) == 1
    assert completed[0].status == "FAILED"
    assert transport.calls == Counter({plan.scoring_place_ids[0]: 1})


def _bundled_release() -> MvpScoredRelease:
    path = next(RELEASE_ROOT.glob("*/release.json"))
    return MvpScoredRelease.model_validate_json(path.read_bytes())


def _relations() -> PublicPlaceRelations:
    return PublicPlaceRelations.model_validate_json(RELATIONS_PATH.read_bytes())


def test_daily_release_adopts_unchanged_baseline_and_replaces_changed_profile() -> None:
    catalog, _ = _artifacts()
    target_content_id = next(
        crosswalk.source_id
        for crosswalk in catalog.places[0].provider_crosswalk
        if crosswalk.provider == "TOUR_API"
    )
    previous_snapshot = _snapshot(
        SyntheticDailyProvider(),
        run_date=date(2026, 9, 5),
    )
    snapshot = _snapshot(
        SyntheticDailyProvider(changed_content_id=target_content_id),
        run_date=date(2026, 9, 6),
        previous_snapshot_sha256=previous_snapshot.snapshot_sha256,
    )
    delta = build_daily_delta(previous_snapshot, snapshot)
    plan = build_incremental_scoring_plan(snapshot=snapshot, delta=delta)
    outcome = execute_incremental_scoring(
        snapshot=snapshot,
        plan=plan,
        transport=SyntheticScoringTransport(),
        catalog_sha256=catalog.catalog_sha256,
        reserve_call=lambda event: None,
    )

    release = materialize_daily_scored_release(
        previous_release=_bundled_release(),
        previous_snapshot=previous_snapshot,
        snapshot=snapshot,
        delta=delta,
        catalog=catalog,
        relations=_relations(),
        results=tuple(outcome.results.values()),
        failures=outcome.failed,
        created_at=COLLECTED_AT,
    )

    target_place_id = delta.changed_place_ids[0]
    assert release.published_count == 100
    assert release.failed == ()
    assert (
        sum(row.lineage.origin == "BUNDLED_BASELINE_ADOPTION" for row in release.profile_entries)
        == 99
    )
    target = next(row for row in release.profile_entries if row.profile.place_id == target_place_id)
    assert target.lineage.origin == "DAILY_GLM"
    assert target.lineage.source_snapshot_sha256 == snapshot.snapshot_sha256
    assert target.profile.evidence_excerpts[0].reference_date == snapshot.run_date


def test_daily_release_excludes_changed_place_after_both_attempts_fail() -> None:
    catalog, _ = _artifacts()
    target_content_id = next(
        crosswalk.source_id
        for crosswalk in catalog.places[0].provider_crosswalk
        if crosswalk.provider == "TOUR_API"
    )
    previous_snapshot = _snapshot(
        SyntheticDailyProvider(),
        run_date=date(2026, 9, 5),
    )
    snapshot = _snapshot(
        SyntheticDailyProvider(changed_content_id=target_content_id),
        run_date=date(2026, 9, 6),
        previous_snapshot_sha256=previous_snapshot.snapshot_sha256,
    )
    delta = build_daily_delta(previous_snapshot, snapshot)
    plan = build_incremental_scoring_plan(snapshot=snapshot, delta=delta)
    place_id = delta.changed_place_ids[0]
    outcome = execute_incremental_scoring(
        snapshot=snapshot,
        plan=plan,
        transport=SyntheticScoringTransport(fail_until={place_id: 2}),
        catalog_sha256=catalog.catalog_sha256,
        reserve_call=lambda event: None,
    )

    release = materialize_daily_scored_release(
        previous_release=_bundled_release(),
        previous_snapshot=previous_snapshot,
        snapshot=snapshot,
        delta=delta,
        catalog=catalog,
        relations=_relations(),
        results=tuple(outcome.results.values()),
        failures=outcome.failed,
        created_at=COLLECTED_AT,
    )

    assert release.published_count == 99
    assert tuple(row.place_id for row in release.failed) == (place_id,)
    assert all(row.profile.place_id != place_id for row in release.profile_entries)


def test_overlay_resolver_uses_bundled_then_last_verified_overlay_on_db_failure() -> None:
    bundled = _bundled_release()

    class SyntheticOverlayReader:
        def __init__(self) -> None:
            self.value = None
            self.failure = False

        def active_release(self):
            if self.failure:
                raise DailyRefreshStoreError("synthetic database failure")
            return self.value

    reader = SyntheticOverlayReader()
    resolver = ActiveReleaseOverlayResolver(
        overlay_reader=reader,  # type: ignore[arg-type]
        bundled_resolver=lambda: bundled,
    )

    assert resolver() is bundled

    catalog, _ = _artifacts()
    target_content_id = next(
        crosswalk.source_id
        for crosswalk in catalog.places[0].provider_crosswalk
        if crosswalk.provider == "TOUR_API"
    )
    previous_snapshot = _snapshot(
        SyntheticDailyProvider(),
        run_date=date(2026, 9, 5),
    )
    snapshot = _snapshot(
        SyntheticDailyProvider(changed_content_id=target_content_id),
        run_date=date(2026, 9, 6),
        previous_snapshot_sha256=previous_snapshot.snapshot_sha256,
    )
    delta = build_daily_delta(previous_snapshot, snapshot)
    plan = build_incremental_scoring_plan(snapshot=snapshot, delta=delta)
    outcome = execute_incremental_scoring(
        snapshot=snapshot,
        plan=plan,
        transport=SyntheticScoringTransport(),
        catalog_sha256=catalog.catalog_sha256,
        reserve_call=lambda event: None,
    )
    overlay = materialize_daily_scored_release(
        previous_release=bundled,
        previous_snapshot=previous_snapshot,
        snapshot=snapshot,
        delta=delta,
        catalog=catalog,
        relations=_relations(),
        results=tuple(outcome.results.values()),
        failures=outcome.failed,
        created_at=COLLECTED_AT,
    )
    reader.value = overlay
    assert resolver() is overlay

    reader.failure = True
    assert resolver() is overlay
