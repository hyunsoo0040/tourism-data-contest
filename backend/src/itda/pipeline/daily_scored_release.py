"""Deterministic per-place lineage materialization for daily scored releases."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import datetime

from itda.contracts.mvp_daily_refresh import (
    DAILY_REFRESH_AUTHORITY_V2,
    DAILY_REFRESH_MEMBERSHIP_SHA256,
    DailyBaselineObservation,
    DailyFailedPlaceV3,
    DailyInputDeltaV2,
    DailyProfileLineage,
    DailyScoredRelease,
    DailyScoringInputSnapshotV2,
    DailySnapshot,
    MvpScoredProfileV2,
    MvpScoredProfileV3,
    MvpScoredReleaseV3,
)
from itda.contracts.mvp_place_scoring import BoundScoringResult
from itda.contracts.mvp_public_catalog import PublicPlaceCatalog, PublicPlaceRelations
from itda.contracts.mvp_scored_release import (
    FailedPlace,
    MvpEvidenceExcerpt,
    MvpScoredProfile,
    MvpScoredRelease,
    information_state_for,
)
from itda.contracts.recommendation import public_relation_sha256
from itda.domain.canonical import canonical_sha256
from itda.pipeline.daily_incremental_scoring import daily_evidence_inventory_sha256

_ENTRY = MvpScoredProfileV2 | MvpScoredProfileV3


def _profile_entry(
    *,
    profile: MvpScoredProfile,
    lineage: DailyProfileLineage,
    source_release_sha256: str | None = None,
    baseline_observation: DailyBaselineObservation | None = None,
) -> MvpScoredProfileV3:
    fields = {
        "profile": profile.model_dump(mode="json"),
        "lineage": lineage.model_dump(mode="json"),
        "source_release_sha256": source_release_sha256,
        "baseline_observation": (
            baseline_observation.model_dump(mode="json")
            if baseline_observation is not None
            else None
        ),
    }
    return MvpScoredProfileV3.model_validate({**fields, "entry_sha256": canonical_sha256(fields)})


def adopt_bundled_baseline(
    *,
    release: MvpScoredRelease,
    snapshot: DailySnapshot,
) -> tuple[MvpScoredProfileV3, ...]:
    from itda.pipeline.daily_public_input import snapshot_semantics

    requests = {row.place_id: row.request for row in snapshot.places}
    if {row.place_id for row in release.profiles}.union(
        row.place_id for row in release.failed
    ) != set(snapshot_semantics(snapshot)):
        raise ValueError("bundled release does not cover baseline PUBLIC-100")
    return tuple(
        _profile_entry(
            profile=profile,
            lineage=DailyProfileLineage(
                origin="BUNDLED_BASELINE_ADOPTION",
                input_request_sha256=profile.scoring_result.request_sha256,
                source_snapshot_sha256=snapshot.snapshot_sha256,
                source_run_date=snapshot.run_date,
                result_sha256=profile.scoring_result.result_sha256,
            ),
            source_release_sha256=release.release_sha256,
            baseline_observation=DailyBaselineObservation(
                snapshot_sha256=snapshot.snapshot_sha256,
                request_sha256=requests[profile.place_id].request_sha256,
                run_date=snapshot.run_date,
            ),
        )
        for profile in release.profiles
        if profile.place_id in requests
    )


def _daily_profile(
    *,
    snapshot: DailySnapshot,
    catalog: PublicPlaceCatalog,
    result: BoundScoringResult,
) -> MvpScoredProfile:
    inputs = {row.place_id: row for row in snapshot.places}
    places = {row.place_id: row for row in catalog.places}
    try:
        row = inputs[result.place_id]
        place = places[result.place_id]
    except KeyError as error:
        raise ValueError("daily result is outside PUBLIC-100") from error
    if (
        result.request_sha256 != row.request.request_sha256
        or result.catalog_sha256 != catalog.catalog_sha256
        or result.evidence_inventory_sha256 != daily_evidence_inventory_sha256(snapshot)
    ):
        raise ValueError("daily result lineage does not match snapshot")
    referenced = tuple(
        sorted(
            {
                evidence_id
                for justification in result.scores.justifications
                for evidence_id in justification.evidence_ids
            }
        )
    )
    if referenced != (row.evidence.evidence_id,):
        raise ValueError("daily result references evidence outside its place input")
    excerpt = MvpEvidenceExcerpt(
        evidence_id=row.evidence.evidence_id,
        excerpt_ko=row.evidence.excerpt,
        source_label_ko=row.evidence.permission_metadata.dataset_title_ko,
        attribution_ko=row.evidence.attribution_text,
        reference_date=row.evidence.reference_date,
        evidence=row.evidence,
    )
    fields = {
        "place_id": row.place_id,
        "place_name_ko": row.request.place.name_ko,
        "duplicate_group_id": place.duplicate_group_id,
        "source_evidence_ids": referenced,
        "evidence_excerpts": (excerpt,),
        "scores": result.scores,
        "condition_scores": result.condition_scores,
        "information_state": information_state_for(result.scores.confidence),
        "recommendation_eligible": True,
        "scoring_result": result,
    }
    serializable = {
        **fields,
        "evidence_excerpts": [excerpt.model_dump(mode="json")],
        "scores": result.scores.model_dump(mode="json"),
        "condition_scores": result.condition_scores.model_dump(mode="json"),
        "information_state": str(information_state_for(result.scores.confidence)),
        "scoring_result": result.model_dump(mode="json"),
    }
    return MvpScoredProfile.model_validate(
        {**fields, "profile_sha256": canonical_sha256(serializable)}
    )


def _failure(place_id: str, reason: str) -> FailedPlace:
    allowed = {
        "PROVIDER_ATTEMPT_FAILED",
        "PROVIDER_RESPONSE_JSON_INVALID",
        "PROVIDER_RESPONSE_SCORE_INVALID",
        "PROVIDER_RESPONSE_JUSTIFICATION_COUNT_INVALID",
        "PROVIDER_RESPONSE_JUSTIFICATION_DIMENSION_INVALID",
        "PROVIDER_RESPONSE_JUSTIFICATION_EVIDENCE_INVALID",
        "PROVIDER_RESPONSE_JUSTIFICATION_TEXT_INVALID",
        "PROVIDER_RESPONSE_JUSTIFICATION_SHAPE_INVALID",
        "PROVIDER_RESPONSE_SHAPE_INVALID",
        "PROVIDER_EVIDENCE_REFERENCE_INVALID",
        "REQUEST_INPUT_TOKEN_LIMIT_EXCEEDED",
    }
    normalized = reason if reason in allowed else "PROVIDER_ATTEMPT_FAILED"
    return FailedPlace.model_validate({"place_id": place_id, "reason": normalized})


def release_input_state(
    release: DailyScoredRelease,
    *,
    baseline: DailySnapshot,
    get_snapshot: Callable[[str], DailySnapshot | None],
) -> tuple[dict[str, _ENTRY], dict[str, DailyFailedPlaceV3]]:
    entries: dict[str, _ENTRY]
    if isinstance(release, MvpScoredRelease):
        entries = {
            r.profile.place_id: r
            for r in adopt_bundled_baseline(
                release=release,
                snapshot=baseline,
            )
        }
        observed = baseline
    else:
        entries = {r.profile.place_id: r for r in release.profile_entries}
        source_snapshot = get_snapshot(release.snapshot_sha256)
        if source_snapshot is None:
            raise ValueError("active release source snapshot is missing")
        observed = source_snapshot
    requests = {r.place_id: r.request.request_sha256 for r in observed.places}
    failed = {}
    for row in release.failed:
        if row.place_id not in requests:
            continue
        if isinstance(row, DailyFailedPlaceV3):
            failed[row.place_id] = row
        else:
            failed[row.place_id] = DailyFailedPlaceV3(
                place_id=row.place_id,
                reason=row.reason,
                input_request_sha256=requests[row.place_id],
                source_snapshot_sha256=observed.snapshot_sha256,
                source_run_date=observed.run_date,
                origin="LEGACY_BASELINE_OBSERVATION",
            )
    return entries, failed


def entry_observed_request(entry: _ENTRY) -> str:
    if isinstance(entry, MvpScoredProfileV3) and entry.baseline_observation is not None:
        return entry.baseline_observation.request_sha256
    return entry.lineage.input_request_sha256


def scoring_targets(
    *,
    snapshot: DailyScoringInputSnapshotV2,
    previous_snapshot: DailySnapshot,
    entries: Mapping[str, _ENTRY],
    failed: Mapping[str, DailyFailedPlaceV3],
) -> tuple[str, ...]:
    previous_available = {r.place_id for r in previous_snapshot.places}
    targets = []
    for row in snapshot.places:
        entry = entries.get(row.place_id)
        failure = failed.get(row.place_id)
        observed = (
            entry_observed_request(entry)
            if entry is not None
            else (failure.input_request_sha256 if failure is not None else None)
        )
        if row.place_id not in previous_available or observed != row.request.request_sha256:
            targets.append(row.place_id)
    return tuple(sorted(targets))


def materialize_daily_scored_release(
    *,
    previous_release: DailyScoredRelease,
    previous_snapshot: DailySnapshot,
    snapshot: DailyScoringInputSnapshotV2,
    delta: DailyInputDeltaV2,
    catalog: PublicPlaceCatalog,
    relations: PublicPlaceRelations,
    results: Sequence[BoundScoringResult],
    failures: Mapping[str, str],
    created_at: datetime,
    scoring_place_ids: tuple[str, ...] | None = None,
    reusable_entries: Mapping[str, _ENTRY] | None = None,
    reusable_failed: Mapping[str, DailyFailedPlaceV3] | None = None,
) -> MvpScoredReleaseV3:
    available = {r.place_id: r for r in snapshot.places}
    changed = (
        set(scoring_place_ids)
        if scoring_place_ids is not None
        else (set(delta.changed_place_ids).intersection(available))
    )
    results_by_id = {row.place_id: row for row in results}
    if len(results_by_id) != len(results):
        raise ValueError("daily results must have unique places")
    if (
        delta.previous_snapshot_sha256 != previous_snapshot.snapshot_sha256
        or delta.snapshot_sha256 != snapshot.snapshot_sha256
        or changed != set(results_by_id).union(failures)
        or set(results_by_id).intersection(failures)
    ):
        raise ValueError("daily release inputs do not exactly cover changed places")
    catalog_ids = tuple(row.place_id for row in catalog.places)
    if canonical_sha256(list(catalog_ids)) != DAILY_REFRESH_MEMBERSHIP_SHA256:
        raise ValueError("daily release catalog membership authority does not match")
    if (
        relations.catalog_sha256 != catalog.catalog_sha256
        or relations.catalog_place_ids != catalog_ids
    ):
        raise ValueError("daily release relations do not match catalog")

    if reusable_entries is None or reusable_failed is None:
        previous_entries, previous_failed = release_input_state(
            previous_release,
            baseline=previous_snapshot,
            get_snapshot=lambda sha: (
                previous_snapshot if sha == previous_snapshot.snapshot_sha256 else None
            ),
        )
    else:
        previous_entries, previous_failed = dict(reusable_entries), dict(reusable_failed)
    entries = {
        place_id: entry
        for place_id, entry in previous_entries.items()
        if place_id in available and place_id not in changed
    }
    failed = {
        place_id: row
        for place_id, row in previous_failed.items()
        if place_id in available and place_id not in changed
    }
    if any(
        entry_observed_request(entry) != available[place_id].request.request_sha256
        for place_id, entry in entries.items()
    ) or any(
        row.input_request_sha256 != available[place_id].request.request_sha256
        for place_id, row in failed.items()
    ):
        raise ValueError("reused input is not reflected by active lineage")
    for place_id, result in results_by_id.items():
        profile = _daily_profile(snapshot=snapshot, catalog=catalog, result=result)
        input_row = next(row for row in snapshot.places if row.place_id == place_id)
        entries[place_id] = _profile_entry(
            profile=profile,
            lineage=DailyProfileLineage(
                origin="DAILY_GLM",
                input_request_sha256=input_row.request.request_sha256,
                source_snapshot_sha256=snapshot.snapshot_sha256,
                source_run_date=snapshot.run_date,
                result_sha256=result.result_sha256,
            ),
        )
        failed.pop(place_id, None)
    for place_id, reason in failures.items():
        entries.pop(place_id, None)
        failed[place_id] = DailyFailedPlaceV3(
            place_id=place_id,
            reason=_failure(place_id, reason).reason,
            input_request_sha256=available[place_id].request.request_sha256,
            source_snapshot_sha256=snapshot.snapshot_sha256,
            source_run_date=snapshot.run_date,
            origin="DAILY_GLM",
        )

    profile_entries = tuple(entries[place_id] for place_id in sorted(entries))
    failed_rows = tuple(failed[place_id] for place_id in sorted(failed))
    if len(profile_entries) < 80:
        raise ValueError("daily release requires at least 80 valid profiles")
    profile_ids = tuple(row.profile.place_id for row in profile_entries)
    members = set(profile_ids)
    relation_pairs = tuple(
        (row.left_place_id, row.right_place_id)
        for row in relations.relations
        if row.left_place_id in members and row.right_place_id in members
    )
    fields = {
        "schema_version": "mvp-scored-release.v3",
        "authority_membership_sha256": DAILY_REFRESH_MEMBERSHIP_SHA256,
        "published_count": len(profile_entries),
        "membership_sha256": canonical_sha256(list(profile_ids)),
        "relation_sha256": public_relation_sha256(profile_ids, relation_pairs),
        "relation_pairs": relation_pairs,
        "profile_entries": profile_entries,
        "failed": failed_rows,
        "excluded": [row.model_dump(mode="json") for row in snapshot.excluded],
        "previous_release_sha256": previous_release.release_sha256,
        "daily_run_date": snapshot.run_date,
        "snapshot_sha256": snapshot.snapshot_sha256,
        "delta_sha256": delta.delta_sha256,
        "authority_sha256": DAILY_REFRESH_AUTHORITY_V2.authority_sha256,
        "created_at": created_at,
    }
    serializable = {
        **fields,
        "profile_entries": [row.model_dump(mode="json") for row in profile_entries],
        "failed": [row.model_dump(mode="json") for row in failed_rows],
        "daily_run_date": snapshot.run_date.isoformat(),
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
    }
    return MvpScoredReleaseV3.model_validate(
        {**fields, "release_sha256": canonical_sha256(serializable)}
    )
