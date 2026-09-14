"""V5 PostgreSQL pins replay the actual kernel over complete synthetic authority.

Fixtures are synthetic policy/ownership cases, never human labels or live data.
"""

from __future__ import annotations

import base64
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import event, func, select

from itda.contracts.grounded_recommendation import GroundedTripInput
from itda.contracts.grounded_release import GroundedReleaseCandidate
from itda.contracts.grounded_run import GroundedRecommendationRun
from itda.contracts.recommendation import RecommendationRequest
from itda.contracts.source_assessment import (
    AssessmentMember,
    AssessmentReleaseManifest,
    ClaimKind,
    PlaceMatch,
    SourceEvidence,
    SourceObservation,
    SourceReceipt,
    SourceService,
    SupportState,
)
from itda.contracts.visual_mood import MoodObservation, VisualMoodDimension
from itda.db.assessment_release import AssessmentReleaseRepository
from itda.db.grounded_run_repositories import GROUNDED_RUN_SCHEMA, GroundedRunRepository
from itda.db.models import (
    RecommendationRequestBindingRow,
    RecommendationResultPinRow,
    RecommendationRunRow,
)
from itda.db.recommendation_repositories import (
    RecommendationPinInvalid,
    RecommendationRequestConflict,
    RecommendationRunRepository,
)
from itda.db.session import create_database_engine, create_session_factory
from itda.db.source_snapshot_repositories import SourceSnapshotRepository
from itda.domain.canonical import canonical_sha256
from itda.domain.grounded_recommendation import rank_grounded
from itda.domain.visual_mood import build_candidate_set, confirm_moods, mood_draft_sha256
from itda.pipeline.destination_evidence import DestinationEvidenceSnapshot
from itda.pipeline.destination_mood import analyze_destination_mood
from itda.pipeline.grounded_assessment import build_assessment
from itda.tourism.accessibility import AccessibilityService, CanonicalTourismPlace
from tests.contract.test_mvp_scored_release import release
from tests.integration.test_grounded_release_pairs import NOW, _hashed
from tests.integration.test_recommendation_runs import _migrate, _persist_profile


def supported_candidate(tag=0):
    raw = release(80)
    created = NOW + timedelta(seconds=tag)
    sources = []
    for index, profile in enumerate(raw.profiles):
        overview = "합성 검증 문장: 전통 건축 이야기와 빛의 색감이 보이는 관광 공간입니다."
        body = {
            "response": {
                "body": {
                    "items": {"item": [{"contentid": str(index), "overview": overview}]},
                    "totalCount": 1,
                }
            }
        }
        body_bytes = json.dumps(body, ensure_ascii=False).encode()
        digest = hashlib.sha256(body_bytes).hexdigest()
        receipt = SourceReceipt(
            service=SourceService.TOUR,
            operation="detailCommon2",
            dataset_id="15101578",
            request_scope={"contentId": str(index)},
            retrieved_at=created,
            reference_date=created.date(),
            status="AVAILABLE",
            http_status=200,
            response_sha256=digest,
            reason="SYNTHETIC_TEST_ONLY",
        )
        match = PlaceMatch(
            place_id=profile.place_id,
            service=SourceService.TOUR,
            provider_entity_id=str(index),
            state="MATCHED",
            method="EXACT_ID_AND_LOCATION",
            region_code="47130",
            evidence=("synthetic exact crosswalk",),
        )
        evidence = SourceEvidence(
            evidence_id="evidence:" + canonical_sha256({"index": index, "tag": tag}),
            receipt=receipt,
            place_match=match,
            scope="PLACE",
            modality="TEXT",
            source_field="overview",
            excerpt=overview,
            quote=overview,
        )
        sources.append(
            _hashed(
                DestinationEvidenceSnapshot,
                dict(
                    place=CanonicalTourismPlace(
                        place_id=profile.place_id, name_ko=profile.place_name_ko
                    ),
                    category="관광지",
                    catalog_row_sha256=canonical_sha256({"synthetic": index}),
                    collected_at=created,
                    receipts=(receipt,),
                    raw_responses=(
                        {
                            "raw_body_base64": base64.b64encode(body_bytes).decode(),
                            "raw_response_sha256": digest,
                            "payload": body,
                        },
                    ),
                    evidence=(evidence,),
                    text_lineage=(),
                    images=(),
                    coverage={"fixture": "SYNTHETIC_TEST_ONLY"},
                ),
                "snapshot_sha256",
            )
        )
    source_hashes = tuple(sorted(canonical_sha256(s.model_dump(mode="json")) for s in sources))
    source_release = canonical_sha256(
        {
            "policy_version": "source-bundle-v1",
            "raw_release_sha256": raw.release_sha256,
            "source_snapshot_sha256": source_hashes,
        }
    )
    assessments = tuple(
        build_assessment(
            profile=profile,
            judgments={
                key: SourceObservation(
                    key=key,
                    claim=ClaimKind.EXPERIENCE,
                    state=SupportState.INFERENCE,
                    value=2,
                    evidence=source.evidence,
                    reference_date=created.date(),
                    reason="synthetic supported scenario",
                )
                for key in ("H1", "H2", "E1", "E2")
            },
            facts={},
            source_release_sha256=source_release,
            assessed_at=created,
        ).bundle
        for profile, source in zip(raw.profiles, sources, strict=True)
    )
    moods = tuple(
        analyze_destination_mood(
            place_id=p.place_id,
            raw_profile_sha256=p.profile_sha256,
            source_release_sha256=source_release,
            assets=(),
            provider=None,
            assessed_at=created,
        )
        for p in raw.profiles
    )
    members = tuple(
        AssessmentMember(
            place_id=a.place_id,
            raw_profile_sha256=a.raw_profile_sha256,
            assessment_bundle_sha256=a.bundle_sha256,
        )
        for a in assessments
    )
    manifest = _hashed(
        AssessmentReleaseManifest,
        dict(
            raw_release_sha256=raw.release_sha256,
            source_snapshot_sha256=source_hashes,
            source_release_sha256=source_release,
            members=members,
            assessment_set_sha256=canonical_sha256(
                {
                    "source_release_sha256": source_release,
                    "members": [m.model_dump(mode="json") for m in members],
                }
            ),
            created_at=created,
        ),
        "manifest_sha256",
    )
    batch = {
        "schema_version": "grounded-destination-batch.v1",
        "scope": "PUBLIC_COMPLETE",
        "model": "glm-5.3-flash",
        "raw_release_sha256": raw.release_sha256,
        "source_release_sha256": source_release,
        "manifest_sha256": manifest.manifest_sha256,
        "fixture_origin": "SYNTHETIC_TEST_ONLY",
        "members": [
            dict(
                place_id=a.place_id,
                raw_profile_sha256=a.raw_profile_sha256,
                assessment_bundle_sha256=a.bundle_sha256,
                mood_bundle_sha256=m.bundle_sha256,
            )
            for a, m in zip(assessments, moods, strict=True)
        ],
    }
    batch["run_sha256"] = canonical_sha256(batch)
    return _hashed(
        GroundedReleaseCandidate,
        dict(
            raw_release=raw,
            manifest=manifest,
            assessments=assessments,
            moods=moods,
            source_snapshots=tuple(s.model_dump(mode="json") for s in sources),
            analysis_run=batch,
            created_at=created,
        ),
        "candidate_sha256",
    )


@pytest.fixture(scope="module")
def database(postgres_harness):
    _migrate(postgres_harness)
    runtime = create_database_engine(postgres_harness.dsns["runtime"])
    admin = create_database_engine(postgres_harness.dsns["admin"])
    factory = create_session_factory(runtime)
    candidates = (supported_candidate(), supported_candidate(1))
    staging = AssessmentReleaseRepository(create_session_factory(admin))
    for candidate in candidates:
        staging.stage(candidate)
    yield (
        runtime,
        factory,
        GroundedRunRepository(factory),
        SourceSnapshotRepository(factory),
        candidates,
    )
    runtime.dispose()
    admin.dispose()


def request(profile, *, trip=None, photo=None):
    return RecommendationRequest(
        request_id="grounded:" + uuid4().hex,
        preference_profile_id=profile.profile_id,
        purpose="MIXED",
        grounded_input=trip or GroundedTripInput(visit_date=NOW.date()),
        photo_job_id=photo.job_id if photo else None,
    )


def run(candidate, profile, req, *, contexts=(), photo=None):
    from itda.application.grounded_context import build_candidates, build_grounded_preference

    preference = build_grounded_preference(profile, req, photo)
    hashes = tuple(sorted(canonical_sha256(p) for p in contexts))
    return rank_grounded(
        candidates=build_candidates(candidate, contexts, preference, user_profile=profile),
        preference=preference,
        candidate_sha256=candidate.candidate_sha256,
        release_sha256=candidate.raw_release.release_sha256,
        source_release_sha256=candidate.manifest.source_release_sha256,
        assessment_manifest_sha256=candidate.manifest.manifest_sha256,
        membership_sha256=candidate.raw_release.membership_sha256,
        relation_sha256=candidate.raw_release.relation_sha256,
        forbidden_pairs=candidate.raw_release.relation_pairs,
        contextual_snapshot_sha256=hashes,
        created_at=NOW + timedelta(minutes=5),
    )


def insert(repo, candidate, profile, req, receipt, *, contexts=(), photo=None):
    return repo.insert_or_recover(
        request_id=req.request_id,
        preference_profile_id=profile.profile_id,
        run=receipt,
        candidate=candidate,
        contextual_snapshot_sha256=tuple(sorted(canonical_sha256(p) for p in contexts)),
        confirmed_mood=photo,
    )


def counts(factory):
    with factory() as session:
        return tuple(
            session.scalar(select(func.count()).select_from(table))
            for table in (
                RecommendationRunRow,
                RecommendationResultPinRow,
                RecommendationRequestBindingRow,
            )
        )


def test_pinned_v5_results_detail_compare_and_small_reference(database):
    engine, factory, repo, _, (candidate, _) = database
    profile = _persist_profile(engine, "grounded-profile:" + uuid4().hex)
    req = request(profile)
    receipt = run(candidate, profile, req)
    persisted, recovered = insert(repo, candidate, profile, req, receipt)
    assert persisted == receipt and not recovered
    assert repo.lookup_schema_for_request(req.request_id) == GROUNDED_RUN_SCHEMA
    assert repo.lookup_schema_for_run(receipt.run_id) == GROUNDED_RUN_SCHEMA
    pinned = repo.load_pinned(receipt.run_id)
    assert (
        pinned.candidate == candidate
        and pinned.contextual_snapshots == ()
        and pinned.confirmed_mood is None
    )
    assert repo.load_results(receipt.run_id).run == receipt
    detail = repo.load_detail(receipt.run_id, receipt.items[0].place_id)
    assert detail.assessment.bundle_sha256 == receipt.items[0].assessment_bundle_sha256
    comparison = repo.load_comparison(receipt.run_id, tuple(i.place_id for i in receipt.items[:2]))
    assert comparison.places[0] == detail
    with factory() as session:
        row = session.get(RecommendationResultPinRow, receipt.run_id)
        assert row.release_snapshot["schema_version"] == "grounded-result-reference.v1"
        assert "raw_release" not in row.release_snapshot
        assert len(json.dumps(row.release_snapshot)) < 2048
    saved = repo.resolve_saved_place_reference(
        candidate_sha256=candidate.candidate_sha256,
        place_id=detail.item.place_id,
        current_candidate_sha256=candidate.candidate_sha256,
    )
    assert saved.state.value == "CURRENT"
    assert (
        RecommendationRunRepository(factory).load_release_snapshot(
            candidate.raw_release.release_sha256
        )
        is None
    )


def test_request_aliases_and_changed_trip_or_candidate_fail_closed(database):
    engine, _, repo, _, (candidate, other) = database
    profile = _persist_profile(engine, "grounded-alias:" + uuid4().hex)
    req = request(profile)
    receipt = run(candidate, profile, req)
    insert(repo, candidate, profile, req, receipt)
    alias = req.model_copy(update={"request_id": "alias:" + uuid4().hex})
    assert insert(repo, candidate, profile, alias, receipt) == (receipt, True)
    assert (
        repo.recover_bound_request(
            request_id=alias.request_id, preference_profile_id=profile.profile_id
        )
        == receipt
    )
    changed = req.model_copy(
        update={"grounded_input": GroundedTripInput(visit_date=NOW.date() + timedelta(days=1))}
    )
    with pytest.raises(RecommendationRequestConflict):
        insert(repo, candidate, profile, changed, run(candidate, profile, changed))
    with pytest.raises(RecommendationRequestConflict):
        insert(repo, other, profile, req, run(other, profile, req))
    assert repo.load_run(receipt.run_id) == receipt


def test_concurrent_identical_aliases_keep_one_run_pin(database):
    engine, factory, repo, _, (candidate, _) = database
    profile = _persist_profile(engine, "grounded-concurrent:" + uuid4().hex)
    req = request(profile)
    receipt = run(candidate, profile, req)
    before = counts(factory)
    aliases = [req.model_copy(update={"request_id": "parallel:" + uuid4().hex}) for _ in range(3)]
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = tuple(pool.map(lambda r: insert(repo, candidate, profile, r, receipt), aliases))
    assert all(value == receipt for value, _ in results)
    after = counts(factory)
    assert tuple(a - b for a, b in zip(after, before, strict=True)) == (1, 1, 3)


def test_failed_alias_flush_rolls_back_new_run_and_pin(database):
    engine, factory, repo, _, (candidate, _) = database
    profile = _persist_profile(engine, "grounded-rollback:" + uuid4().hex)
    req = request(profile)
    receipt = run(candidate, profile, req)
    before = counts(factory)

    def fail(session, *_):
        if any(
            isinstance(row, RecommendationRequestBindingRow) and row.request_id == req.request_id
            for row in session.new
        ):
            raise RuntimeError("injected failure after run and pin inserts")

    event.listen(factory, "before_flush", fail)
    try:
        with pytest.raises(RuntimeError, match="injected failure"):
            insert(repo, candidate, profile, req, receipt)
    finally:
        event.remove(factory, "before_flush", fail)
    assert counts(factory) == before


def test_counterfeit_self_consistent_confidence_is_rejected_by_candidate_replay(database):
    engine, _, repo, _, (candidate, _) = database
    profile = _persist_profile(engine, "grounded-counterfeit:" + uuid4().hex)
    req = request(profile)
    receipt = run(candidate, profile, req)
    payload = receipt.model_dump(mode="json")
    original_confidence = payload["items"][0]["overall_confidence"]
    # Keep the same warning-confidence band so this is a self-consistent forged
    # receipt, not merely an arithmetic/schema failure caught before persistence.
    payload["items"][0]["overall_confidence"] = (
        99
        if original_confidence >= 65 and original_confidence != 99
        else 98
        if original_confidence >= 65
        else 64
        if original_confidence != 64
        else 63
    )
    digest = canonical_sha256(
        {k: v for k, v in payload.items() if k not in {"created_at", "canonical_sha256", "run_id"}}
    )
    payload.update(canonical_sha256=digest, run_id="recommendation-run:" + digest[:32])
    counterfeit = GroundedRecommendationRun.model_validate(payload)
    with pytest.raises(RecommendationPinInvalid, match="kernel replay"):
        insert(repo, candidate, profile, req, counterfeit)


def test_resealed_reference_to_another_valid_pair_fails_on_read(database, postgres_harness):
    engine, _, repo, _, (candidate, other) = database
    profile = _persist_profile(engine, "grounded-wrong-pin:" + uuid4().hex)
    req = request(profile)
    receipt = run(candidate, profile, req)
    insert(repo, candidate, profile, req, receipt)
    reference = {
        "schema_version": "grounded-result-reference.v1",
        "candidate_sha256": other.candidate_sha256,
        "contextual_snapshot_sha256": [],
        "confirmed_mood": None,
    }
    reference["reference_sha256"] = canonical_sha256(reference)
    with postgres_harness.connect("admin") as connection:
        connection.execute("ALTER TABLE app.recommendation_result_pins DISABLE TRIGGER USER")
        connection.execute(
            "UPDATE app.recommendation_result_pins SET release_snapshot=%s::jsonb, "
            "snapshot_sha256=%s WHERE run_id=%s",
            (json.dumps(reference), reference["reference_sha256"], receipt.run_id),
        )
        connection.execute("ALTER TABLE app.recommendation_result_pins ENABLE TRIGGER USER")
    with pytest.raises(RecommendationPinInvalid, match="authority differ"):
        repo.load_pinned(receipt.run_id)


def test_context_source_pins_are_required_and_tamper_evident(database, postgres_harness):
    engine, _, repo, sources, (candidate, _) = database
    profile = _persist_profile(engine, "grounded-context:" + uuid4().hex)
    place = candidate.raw_release.profiles[0]
    snapshot = AccessibilityService(
        client=None,
        places=(CanonicalTourismPlace(place_id=place.place_id, name_ko=place.place_name_ko),),
        clock=lambda: NOW,
    ).fetch(place.place_id)
    payload = snapshot.model_dump(mode="json")
    contexts = (payload,)
    req = request(profile)
    receipt = run(candidate, profile, req, contexts=contexts)
    with pytest.raises(RecommendationPinInvalid, match="snapshot missing"):
        insert(repo, candidate, profile, req, receipt, contexts=contexts)
    digest = sources.put_source(payload)
    insert(repo, candidate, profile, req, receipt, contexts=contexts)
    assert repo.load_pinned(receipt.run_id).contextual_snapshots == contexts
    # Simulate disk/admin corruption in this isolated database only. Ordinary
    # runtime mutations are rejected by the immutable source table trigger.
    with postgres_harness.connect("admin") as connection:
        connection.execute(
            "ALTER TABLE app.tourism_source_snapshots "
            "DISABLE TRIGGER immutable_tourism_source_snapshots"
        )
        connection.execute(
            "UPDATE app.tourism_source_snapshots SET payload='{}'::jsonb WHERE snapshot_sha256=%s",
            (digest,),
        )
        connection.execute(
            "ALTER TABLE app.tourism_source_snapshots "
            "ENABLE TRIGGER immutable_tourism_source_snapshots"
        )
    with pytest.raises(RecommendationPinInvalid):
        repo.load_run(receipt.run_id)


def test_confirmed_mood_small_receipt_is_replayed_without_private_photo_storage(database):
    engine, _, repo, _, (candidate, _) = database
    profile = _persist_profile(engine, "grounded-photo:" + uuid4().hex)
    job = "a" * 64
    batch = build_candidate_set(
        job_id=job,
        image_index=1,
        image_sha256="b" * 64,
        provider_id="synthetic-photo-fixture",
        analysis_kind="SYNTHETIC",
        model=None,
        observations=tuple(
            MoodObservation(dimension=d, state="UNKNOWN", level=None, certainty="LOW")
            for d in VisualMoodDimension
        ),
    )
    photo = confirm_moods(
        job_id=job,
        profile_id=profile.profile_id,
        batches=(batch,),
        choices=(),
        draft_sha256=mood_draft_sha256(job_id=job, profile_id=profile.profile_id, batches=(batch,)),
    )
    req = request(profile, photo=photo)
    receipt = run(candidate, profile, req, photo=photo)
    insert(repo, candidate, profile, req, receipt, photo=photo)
    pinned = repo.load_pinned(receipt.run_id)
    assert pinned.confirmed_mood == photo
    assert all(value is None for value in pinned.run.preference.mood_targets.values())
    assert pinned.run.authority.photo_input_sha256 == photo.receipt_id
    assert "payload_sha256" not in pinned.confirmed_mood.model_dump_json()
    assert (
        repo.recover_bound_request(
            request_id=req.request_id, preference_profile_id=profile.profile_id
        )
        == receipt
    )
