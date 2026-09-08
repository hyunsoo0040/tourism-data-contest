from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta

import pytest

from itda.collectors.base import parse_provider_envelope
from itda.contracts.mvp_daily_refresh import (
    DAILY_REFRESH_AUTHORITY,
    DailyScoringInputSnapshot,
    MvpScoredReleaseV2,
    parse_daily_scored_release,
    parse_daily_snapshot,
)
from itda.domain.canonical import canonical_sha256
from itda.operating.service import ProviderPlace
from itda.pipeline.daily_public_input import (
    DailyCollectionIncomplete,
    _validated_item,
    build_daily_delta,
)
from itda.pipeline.daily_refresh import run_daily_refresh
from tests.pipeline.test_daily_public_input import (
    SyntheticDailyProvider,
    SyntheticScoringTransport,
    _bundled_release,
    _snapshot,
)
from tests.pipeline.test_daily_refresh import CATALOG, EVIDENCE, RELATIONS, SyntheticRefreshStore

START = date(2026, 9, 1)


def content_id(place_id: str) -> str:
    place = next(r for r in CATALOG.places if r.place_id == place_id)
    return next(r.source_id for r in place.provider_crosswalk if r.provider == "TOUR_API")


class AvailabilityProvider(SyntheticDailyProvider):
    def __init__(self, *, unavailable=(), ended=(), intro_empty=(), **kwargs):
        super().__init__(**kwargs)
        self.unavailable = {content_id(p) for p in unavailable}
        self.ended = {content_id(p) for p in ended}
        self.intro_empty = {content_id(p) for p in intro_empty}

    def fetch_common(self, place):
        response = super().fetch_common(place)
        if place.content_id not in self.unavailable:
            return response
        return self._response(
            "detailCommon2",
            {
                "response": {
                    "header": {"resultCode": "0000"},
                    "body": {"items": "", "totalCount": 0},
                },
            },
        )

    def fetch_intro(self, place):
        response = super().fetch_intro(place)
        if place.content_id in self.intro_empty:
            return self._response(
                "detailIntro2",
                {
                    "response": {
                        "header": {"resultCode": "03"},
                        "body": {"items": {"item": []}, "totalCount": "0"},
                    },
                },
            )
        if place.content_id in self.ended:
            payload = deepcopy(response.payload)
            payload["response"]["body"]["items"]["item"].update(
                eventstartdate="20250801",
                eventenddate="20250831",
            )
            return self._response("detailIntro2", payload)
        return response


class PersistentStore(SyntheticRefreshStore):
    def latest_snapshot(self):
        return self.snapshots[-1] if self.snapshots else self.previous

    def baseline_snapshot(self):
        return self.previous if self.previous is not None else self.snapshots[0]


def run_day(store, day, provider, transport=None):
    def scorer():
        if transport is None:
            raise AssertionError("이 경로에서 GLM 객체를 생성하면 안 됩니다")
        return transport

    return run_daily_refresh(
        run_date=day,
        collected_at=datetime.combine(day, datetime.min.time(), tzinfo=UTC),
        catalog=CATALOG,
        evidence_inventory=EVIDENCE,
        relations=RELATIONS,
        provider=provider,
        store=store,
        active_release_resolver=lambda: (
            store.published[-1] if store.published else _bundled_release()
        ),
        scoring_transport_factory=scorer,
    )


@pytest.mark.parametrize("code", ["00", "0000", "03"])
@pytest.mark.parametrize("items", [None, "", [], {}, {"item": []}, {"item": None}, {"item": {}}])
def test_explicit_empty_json_envelopes(code, items):
    raw = json.dumps(
        {"response": {"header": {"resultCode": code}, "body": {"items": items, "totalCount": 0}}}
    ).encode()
    payload, parsed_code, _ = parse_provider_envelope(raw, content_type="application/json")
    response = SyntheticDailyProvider()._response("detailCommon2", payload)
    response = replace(response, provider_result_code=parsed_code)
    assert _validated_item(response, ProviderPlace("123", "15")) is None


@pytest.mark.parametrize("code", ["0000", "03"])
def test_empty_xml_uses_shared_parser(code):
    raw = (
        f"<response><header><resultCode>{code}</resultCode></header>"
        "<body><items/><totalCount>0</totalCount></body></response>"
    ).encode()
    payload, parsed_code, _ = parse_provider_envelope(raw, content_type="application/xml")
    response = replace(
        SyntheticDailyProvider()._response("detailCommon2", payload),
        provider_result_code=parsed_code,
    )
    assert _validated_item(response, ProviderPlace("123", "15")) is None


@pytest.mark.parametrize(
    "patch",
    [
        {"header": None},
        {"header": {}},
        {"header": {"resultCode": "30"}},
        {"body": {"items": "", "totalCount": 1}},
        {"body": {"items": ""}},
        {"body": {"items": "", "totalCount": True}},
        {"body": {"items": {"item": {"contentid": "123"}}, "totalCount": 0}},
        {"body": {"items": {"nested": {"item": []}}, "totalCount": 0}},
        {"body": {"items": {"item": {"contentid": "wrong"}}, "totalCount": 1}},
        {"body": {"items": {"item": {"contentid": "123", "contenttypeid": "12"}}, "totalCount": 1}},
        {
            "header": {"resultCode": "03"},
            "body": {"items": {"item": {"contentid": "123"}}, "totalCount": 1},
        },
    ],
)
def test_empty_is_not_inferred_from_malformed_or_error_envelope(patch):
    envelope = {"header": {"resultCode": "0000"}, "body": {"items": "", "totalCount": 0}}
    envelope.update(patch)
    response = SyntheticDailyProvider()._response("detailCommon2", {"response": envelope})
    with pytest.raises(DailyCollectionIncomplete):
        _validated_item(response, ProviderPlace("123", "15"))


def test_unavailable_skips_intro_but_intro_empty_keeps_place():
    first, second = [p.place_id for p in CATALOG.places[:2]]
    provider = AvailabilityProvider(unavailable=[first], intro_empty=[second])
    snapshot = _snapshot(provider, run_date=START)
    assert len(snapshot.places) == 99
    assert len(snapshot.excluded) == 1
    assert snapshot.excluded[0].place_id == first
    assert snapshot.excluded[0].state == "INFORMATION_UNAVAILABLE"
    assert snapshot.excluded[0].intro is None
    assert snapshot.excluded[0].event_end_date is None
    assert content_id(first) not in {p.content_id for p in provider.intro_calls}
    kept = next(p for p in snapshot.places if p.place_id == second)
    assert "운영 정보:" not in kept.evidence.excerpt


@pytest.mark.parametrize(
    "end,day,excluded",
    [
        ("20260902", START, False),
        ("20260901", START, False),
        ("20260831", START, True),
    ],
)
def test_event_end_date_uses_fixed_run_date(end, day, excluded):
    target = next(p for p in CATALOG.places if p.category == "축제·공연·행사")

    class EventProvider(SyntheticDailyProvider):
        def fetch_intro(self, place):
            response = super().fetch_intro(place)
            if place.content_id != content_id(target.place_id):
                return response
            payload = deepcopy(response.payload)
            payload["response"]["body"]["items"]["item"]["eventenddate"] = end
            return self._response("detailIntro2", payload)

    snapshot = _snapshot(EventProvider(), run_date=day)
    assert (target.place_id in {p.place_id for p in snapshot.excluded}) is excluded
    if excluded:
        assert snapshot.excluded[0].state == "EVENT_ENDED"


@pytest.mark.parametrize(
    "start,end",
    [
        (None, "20260230"),
        (None, "2026-08-31"),
        (None, 20260831),
        ("20260901", "20260831"),
        ("bad", "20260831"),
    ],
)
def test_invalid_official_event_date_rejects_collection(start, end):
    class InvalidDateProvider(SyntheticDailyProvider):
        def fetch_intro(self, place):
            response = super().fetch_intro(place)
            if place.content_type_id != "15":
                return response
            payload = deepcopy(response.payload)
            payload["response"]["body"]["items"]["item"].update(
                eventstartdate=start,
                eventenddate=end,
            )
            return self._response("detailIntro2", payload)

    with pytest.raises(DailyCollectionIncomplete) as error:
        _snapshot(InvalidDateProvider(), run_date=START)
    assert error.value.failure.operation == "detailIntro2"
    assert error.value.failure.failure_code in {"EVENT_DATE_INVALID", "EVENT_DATE_RANGE_INVALID"}


@pytest.mark.parametrize(
    "available,status",
    [
        (99, "RELEASE_ACTIVATED"),
        (80, "RELEASE_ACTIVATED"),
        (79, "RELEASE_REJECTED"),
        (0, "RELEASE_REJECTED"),
    ],
)
def test_first_baseline_prunes_without_any_glm_or_plan(available, status):
    excluded_ids = [p.place_id for p in CATALOG.places[available:]]
    store = PersistentStore()
    outcome = run_day(store, START, AvailabilityProvider(unavailable=excluded_ids))
    assert outcome.status == status
    assert outcome.call_count == 0
    assert len(store.snapshots[0].places) == available
    assert store.plans == store.reservations == []
    if available < 80:
        assert store.published == store.activations == []
        return
    release = store.published[0]
    assert release.published_count == available
    assert {p.place_id for p in release.excluded} == set(excluded_ids)
    bundled = {p.place_id: p for p in _bundled_release().profiles}
    requests = {p.place_id: p.request.request_sha256 for p in store.snapshots[0].places}
    for entry in release.profile_entries:
        assert entry.profile == bundled[entry.profile.place_id]
        assert entry.lineage.input_request_sha256 == entry.profile.scoring_result.request_sha256
        assert entry.baseline_observation.request_sha256 == requests[entry.profile.place_id]
        assert entry.baseline_observation.request_sha256 != entry.lineage.input_request_sha256


def test_exclusion_only_release_metadata_noop_and_reappearance():
    first, second = [p.place_id for p in CATALOG.places[:2]]
    store = PersistentStore()
    assert run_day(store, START, AvailabilityProvider()).status == "BASELINE_RECORDED"
    assert (
        run_day(store, START + timedelta(days=1), AvailabilityProvider(unavailable=[first])).status
        == "RELEASE_ACTIVATED"
    )
    original = store.published[-1]
    assert (
        run_day(
            store,
            START + timedelta(days=2),
            AvailabilityProvider(unavailable=[first], metadata_version="2"),
        ).status
        == "NO_CHANGES"
    )
    assert store.published == [original]
    assert (
        run_day(
            store, START + timedelta(days=3), AvailabilityProvider(unavailable=[first, second])
        ).status
        == "RELEASE_ACTIVATED"
    )
    retained = store.published[-1]
    assert (
        retained.profile_entries[0].baseline_observation.snapshot_sha256
        == store.snapshots[0].snapshot_sha256
    )
    transport = SyntheticScoringTransport()
    outcome = run_day(
        store, START + timedelta(days=4), AvailabilityProvider(unavailable=[second]), transport
    )
    assert outcome.call_count == 1
    assert set(transport.calls) == {first}
    assert (
        next(
            p for p in store.published[-1].profile_entries if p.profile.place_id == first
        ).lineage.origin
        == "DAILY_GLM"
    )


def test_failed_input_is_not_retried_on_later_zero_call_releases():
    first, second, third = [p.place_id for p in CATALOG.places[:3]]
    store = PersistentStore()
    run_day(store, START, AvailabilityProvider())
    outcome = run_day(
        store,
        START + timedelta(days=1),
        AvailabilityProvider(changed_content_id=content_id(first)),
        SyntheticScoringTransport(fail_until={first: 2}),
    )
    assert outcome.call_count == 2
    failure = store.published[-1].failed[0]
    assert failure.place_id == first
    for offset, absent in [(2, [second]), (3, [second, third])]:
        outcome = run_day(
            store,
            START + timedelta(days=offset),
            AvailabilityProvider(unavailable=absent, changed_content_id=content_id(first)),
        )
        assert outcome.call_count == 0
        assert store.published[-1].failed == (failure,)
    assert (
        run_day(
            store,
            START + timedelta(days=4),
            AvailabilityProvider(unavailable=[second, third], changed_content_id=content_id(first)),
        ).status
        == "NO_CHANGES"
    )


def test_rejected_release_is_reconciled_against_active_not_latest_snapshot():
    first = CATALOG.places[0].place_id
    absent = [p.place_id for p in CATALOG.places[80:]]
    store = PersistentStore()
    run_day(store, START, AvailabilityProvider())
    run_day(store, START + timedelta(days=1), AvailabilityProvider(unavailable=absent))
    active = store.published[-1]
    outcome = run_day(
        store,
        START + timedelta(days=2),
        AvailabilityProvider(unavailable=absent, changed_content_id=content_id(first)),
        SyntheticScoringTransport(fail_until={first: 2}),
    )
    assert outcome.status == "RELEASE_REJECTED"
    assert store.published[-1] == active
    outcome = run_day(
        store,
        START + timedelta(days=3),
        AvailabilityProvider(unavailable=absent, changed_content_id=content_id(first)),
        SyntheticScoringTransport(),
    )
    assert outcome.status == "RELEASE_ACTIVATED"
    assert outcome.changed_count == 0
    assert outcome.call_count == 1


def test_old_snapshot_and_release_payloads_keep_original_hashes():
    current = _snapshot(SyntheticDailyProvider(), run_date=START)
    old_fields = current.model_dump(mode="json", exclude={"excluded", "snapshot_sha256"})
    old_fields.update(
        schema_version="mvp-daily-scoring-input-snapshot.v1",
        authority_sha256=DAILY_REFRESH_AUTHORITY.authority_sha256,
    )
    old = {**old_fields, "snapshot_sha256": canonical_sha256(old_fields)}
    parsed = parse_daily_snapshot(old)
    assert isinstance(parsed, DailyScoringInputSnapshot)
    assert parsed.model_dump(mode="json") == old
    assert build_daily_delta(parsed, current).changed_place_ids == ()
    bundled = _bundled_release()
    assert parse_daily_scored_release(bundled.model_dump(mode="json")) == bundled
    store = PersistentStore(previous=parsed)
    run_day(store, START + timedelta(days=1), AvailabilityProvider(), SyntheticScoringTransport())
    entries = []
    for profile in bundled.profiles:
        fields = {
            "profile": profile.model_dump(mode="json"),
            "lineage": {
                "origin": "BUNDLED_BASELINE_ADOPTION",
                "input_request_sha256": next(
                    r.request.request_sha256
                    for r in parsed.places
                    if r.place_id == profile.place_id
                ),
                "source_snapshot_sha256": parsed.snapshot_sha256,
                "source_run_date": START.isoformat(),
                "result_sha256": profile.scoring_result.result_sha256,
            },
        }
        entries.append({**fields, "entry_sha256": canonical_sha256(fields)})
    fields = {
        "schema_version": "mvp-scored-release.v2",
        "authority_membership_sha256": current.membership_sha256,
        "published_count": 100,
        "membership_sha256": bundled.membership_sha256,
        "relation_sha256": bundled.relation_sha256,
        "relation_pairs": bundled.model_dump(mode="json")["relation_pairs"],
        "profile_entries": entries,
        "failed": [],
        "previous_release_sha256": bundled.release_sha256,
        "daily_run_date": START.isoformat(),
        "snapshot_sha256": parsed.snapshot_sha256,
        "delta_sha256": "d" * 64,
        "authority_sha256": DAILY_REFRESH_AUTHORITY.authority_sha256,
        "created_at": "2026-09-01T00:00:00Z",
    }
    payload = {**fields, "release_sha256": canonical_sha256(fields)}
    assert isinstance(parse_daily_scored_release(payload), MvpScoredReleaseV2)
    assert parse_daily_scored_release(payload).model_dump(mode="json") == payload
    _assert_pinned_round_trip(parse_daily_scored_release(payload))
    _assert_pinned_round_trip(bundled)


def _assert_pinned_round_trip(snapshot):
    from itda.contracts.recommendation import PublicRelationAuthority, RecommendationPreference
    from itda.db.recommendation_repositories import (
        RecommendationRunRepository,
        _pin_row,
        _run_row,
        _validate_pinned_rows,
    )
    from itda.domain.mvp_recommendation import create_mvp_recommendation_run
    from tests.unit.test_recommendation_kernel import _preference_payload

    run = create_mvp_recommendation_run(
        snapshot.profiles,
        release_sha256=snapshot.release_sha256,
        membership_sha256=snapshot.membership_sha256,
        relation_authority=PublicRelationAuthority(
            relation_sha256=snapshot.relation_sha256,
            place_ids=tuple(p.place_id for p in snapshot.profiles),
            pairs=snapshot.relation_pairs,
        ),
        preference=RecommendationPreference.model_validate(_preference_payload()),
        created_at=datetime(2026, 9, 1, tzinfo=UTC),
    )
    pin = _pin_row(run=run, release_snapshot=snapshot)
    restored = _validate_pinned_rows(
        _run_row(
            request_id="availability-pin-test",
            preference_profile_id=run.preference.profile_id,
            run=run,
        ),
        pin,
    )
    assert restored.release_snapshot.model_dump(mode="json") == snapshot.model_dump(mode="json")
    assert restored.run == run
    repo = object.__new__(RecommendationRunRepository)
    repo.load_pinned = lambda _: restored
    results = repo.load_results(run.run_id)
    assert results.release_disclosure.profile_schema_version == snapshot.schema_version
    assert repo.load_detail(run.run_id, run.items[0].place_id).item == run.items[0]
    assert run.candidate_place_ids == tuple(p.place_id for p in snapshot.profiles)


def test_v3_pin_replays_original_release_after_later_exclusions():
    store = PersistentStore()
    first, second = [p.place_id for p in CATALOG.places[:2]]
    run_day(store, START, AvailabilityProvider(unavailable=[first]))
    pinned = store.published[-1]
    run_day(store, START + timedelta(days=1), AvailabilityProvider(unavailable=[first, second]))
    assert second not in {p.place_id for p in store.published[-1].profiles}
    assert second in {p.place_id for p in pinned.profiles}
    _assert_pinned_round_trip(pinned)
    _assert_pinned_round_trip(store.published[-1])


def test_invalid_overlay_does_not_fall_back_to_bundled():
    from itda.db.mvp_release_overlay import ActiveReleaseOverlayResolver, DailyReleasePayloadInvalid

    class InvalidReader:
        def active_release(self):
            raise DailyReleasePayloadInvalid("synthetic invalid version")

    resolver = ActiveReleaseOverlayResolver(
        overlay_reader=InvalidReader(),
        bundled_resolver=_bundled_release,
    )
    with pytest.raises(DailyReleasePayloadInvalid):
        resolver()
    for parser in (parse_daily_snapshot, parse_daily_scored_release):
        with pytest.raises(ValueError, match="unknown"):
            parser({"schema_version": "unknown.v99"})
