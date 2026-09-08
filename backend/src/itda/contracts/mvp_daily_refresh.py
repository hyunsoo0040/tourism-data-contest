"""Strict contracts for bounded daily PUBLIC-100 GLM refreshes."""

from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StrictContract, require_utc
from itda.contracts.mvp_place_scoring import (
    GLM_CODING_ENDPOINT,
    GLM_MODEL,
    MVP_SCORING_PROMPT_SHA256,
    PublicScoringRequest,
)
from itda.contracts.mvp_public_catalog import PublicEvidence, PublicPlaceId
from itda.contracts.mvp_scored_release import FailedPlace, MvpScoredProfile, MvpScoredRelease
from itda.domain.canonical import canonical_sha256

DAILY_REFRESH_MEMBERSHIP_SHA256 = "cdd573f635259b4ac35becdcecdc72f00795cb768d21a003ca0e30fbb9b501f9"
DAILY_REFRESH_MAXIMUM_CALLS = 200
DAILY_REFRESH_RETRY_LIMIT = 1
DAILY_REFRESH_CONCURRENCY = 1


class DailyRefreshRunStatus(StrEnum):
    RUNNING = "RUNNING"
    BASELINE_RECORDED = "BASELINE_RECORDED"
    NO_CHANGES = "NO_CHANGES"
    COLLECTION_INCOMPLETE = "COLLECTION_INCOMPLETE"
    SCORING_FAILED = "SCORING_FAILED"
    RELEASE_REJECTED = "RELEASE_REJECTED"
    RELEASE_ACTIVATED = "RELEASE_ACTIVATED"
    INTERRUPTED = "INTERRUPTED"


class DailyRefreshAuthority(StrictContract):
    schema_version: Literal["mvp-daily-glm-refresh-authority.v1"]
    region: Literal["경주시"]
    pool: Literal["PUBLIC"]
    membership_sha256: Sha256
    tour_api_operations: tuple[Literal["detailCommon2"], Literal["detailIntro2"]]
    model: Literal["glm-5.3-flash"]
    endpoint: Literal["https://api.z.ai/api/coding/paas/v4/chat/completions"]
    prompt_sha256: Sha256
    timezone: Literal["Asia/Seoul"]
    local_hour: Literal[8]
    maximum_calls: Literal[200]
    concurrency: Literal[1]
    retry_limit_per_place: Literal[1]
    public_only: Literal[True]
    fallback: Literal[False]
    authority_sha256: Sha256

    @model_validator(mode="after")
    def validate_authority(self) -> Self:
        if self.membership_sha256 != DAILY_REFRESH_MEMBERSHIP_SHA256:
            raise ValueError("daily refresh membership authority does not match")
        expected = canonical_sha256(self.model_dump(exclude={"authority_sha256"}, mode="json"))
        if self.authority_sha256 != expected:
            raise ValueError("daily refresh authority hash does not match")
        return self


_AUTHORITY_FIELDS = {
    "schema_version": "mvp-daily-glm-refresh-authority.v1",
    "region": "경주시",
    "pool": "PUBLIC",
    "membership_sha256": DAILY_REFRESH_MEMBERSHIP_SHA256,
    "tour_api_operations": ("detailCommon2", "detailIntro2"),
    "model": GLM_MODEL,
    "endpoint": GLM_CODING_ENDPOINT,
    "prompt_sha256": MVP_SCORING_PROMPT_SHA256,
    "timezone": "Asia/Seoul",
    "local_hour": 8,
    "maximum_calls": DAILY_REFRESH_MAXIMUM_CALLS,
    "concurrency": DAILY_REFRESH_CONCURRENCY,
    "retry_limit_per_place": DAILY_REFRESH_RETRY_LIMIT,
    "public_only": True,
    "fallback": False,
}
DAILY_REFRESH_AUTHORITY = DailyRefreshAuthority.model_validate(
    {
        **_AUTHORITY_FIELDS,
        "authority_sha256": canonical_sha256(_AUTHORITY_FIELDS),
    }
)


class DailyPlaceInput(StrictContract):
    place_id: PublicPlaceId
    content_id: Annotated[str, Field(strict=True, pattern=r"^[0-9]{1,32}$")]
    content_type_id: Annotated[str, Field(strict=True, pattern=r"^[0-9]{1,2}$")]
    request: PublicScoringRequest
    evidence: PublicEvidence
    common_response_sha256: Sha256
    intro_response_sha256: Sha256
    common_provider_modifiedtime: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=40)
    ] = None
    intro_provider_modifiedtime: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=40)
    ] = None
    row_sha256: Sha256

    @model_validator(mode="after")
    def validate_row(self) -> Self:
        if self.request.place.place_id != self.place_id:
            raise ValueError("daily input request place does not match")
        if (
            self.evidence.provider != "TOUR_API"
            or self.evidence.provider_source_id != self.content_id
            or tuple(row.evidence_id for row in self.request.evidence)
            != (self.evidence.evidence_id,)
            or self.request.evidence[0].excerpt != self.evidence.excerpt
        ):
            raise ValueError("daily input evidence does not match request")
        expected = canonical_sha256(self.model_dump(exclude={"row_sha256"}, mode="json"))
        if self.row_sha256 != expected:
            raise ValueError("daily input row hash does not match")
        return self


class DailyScoringInputSnapshot(StrictContract):
    schema_version: Literal["mvp-daily-scoring-input-snapshot.v1"]
    run_date: date
    collected_at: datetime
    authority_sha256: Sha256
    membership_sha256: Sha256
    previous_snapshot_sha256: Sha256 | None
    places: Annotated[tuple[DailyPlaceInput, ...], Field(min_length=100, max_length=100)]
    snapshot_sha256: Sha256

    @model_validator(mode="after")
    def validate_snapshot(self) -> Self:
        require_utc(self.collected_at, field_name="collected_at")
        ids = tuple(row.place_id for row in self.places)
        if ids != tuple(sorted(ids)) or len(set(ids)) != 100:
            raise ValueError("daily snapshot requires exactly 100 sorted places")
        if self.authority_sha256 != DAILY_REFRESH_AUTHORITY.authority_sha256:
            raise ValueError("daily snapshot authority does not match")
        if self.membership_sha256 != DAILY_REFRESH_MEMBERSHIP_SHA256:
            raise ValueError("daily snapshot membership does not match")
        expected = canonical_sha256(self.model_dump(exclude={"snapshot_sha256"}, mode="json"))
        if self.snapshot_sha256 != expected:
            raise ValueError("daily snapshot hash does not match")
        return self


class DailyInputDelta(StrictContract):
    schema_version: Literal["mvp-daily-input-delta.v1"]
    previous_snapshot_sha256: Sha256
    snapshot_sha256: Sha256
    changed_place_ids: tuple[PublicPlaceId, ...]
    unchanged_place_ids: tuple[PublicPlaceId, ...]
    delta_sha256: Sha256

    @model_validator(mode="after")
    def validate_delta(self) -> Self:
        changed = tuple(self.changed_place_ids)
        unchanged = tuple(self.unchanged_place_ids)
        if changed != tuple(sorted(changed)) or unchanged != tuple(sorted(unchanged)):
            raise ValueError("daily delta place IDs must use canonical order")
        if len(changed) != len(set(changed)) or len(unchanged) != len(set(unchanged)):
            raise ValueError("daily delta place IDs must be unique")
        if set(changed).intersection(unchanged) or len(changed) + len(unchanged) != 100:
            raise ValueError("daily delta must partition PUBLIC-100")
        expected = canonical_sha256(self.model_dump(exclude={"delta_sha256"}, mode="json"))
        if self.delta_sha256 != expected:
            raise ValueError("daily delta hash does not match")
        return self


class DailyIncrementalScoringPlan(StrictContract):
    schema_version: Literal["mvp-daily-incremental-scoring-plan.v1"]
    run_date: date
    authority_sha256: Sha256
    snapshot_sha256: Sha256
    delta_sha256: Sha256
    endpoint: Literal["https://api.z.ai/api/coding/paas/v4/chat/completions"]
    model: Literal["glm-5.3-flash"]
    prompt_sha256: Sha256
    changed_place_ids: Annotated[tuple[PublicPlaceId, ...], Field(min_length=1, max_length=100)]
    request_sha256: Annotated[tuple[Sha256, ...], Field(min_length=1, max_length=100)]
    first_pass_count: Annotated[int, Field(strict=True, ge=1, le=100)]
    retry_limit_per_place: Literal[1]
    maximum_calls: Literal[200]
    concurrency: Literal[1]
    fallback: Literal[False]
    pay_as_you_go_fallback: Literal[False]
    plan_sha256: Sha256

    @model_validator(mode="after")
    def validate_plan(self) -> Self:
        if self.changed_place_ids != tuple(sorted(self.changed_place_ids)):
            raise ValueError("daily scoring plan places must use canonical order")
        if len(set(self.changed_place_ids)) != len(self.changed_place_ids):
            raise ValueError("daily scoring plan places must be unique")
        if len(self.request_sha256) != len(self.changed_place_ids):
            raise ValueError("daily scoring plan request bindings do not match")
        if self.first_pass_count != len(self.changed_place_ids):
            raise ValueError("daily first pass count does not match")
        if self.authority_sha256 != DAILY_REFRESH_AUTHORITY.authority_sha256:
            raise ValueError("daily scoring plan authority does not match")
        expected = canonical_sha256(self.model_dump(exclude={"plan_sha256"}, mode="json"))
        if self.plan_sha256 != expected:
            raise ValueError("daily scoring plan hash does not match")
        return self


class DailyProfileLineage(StrictContract):
    origin: Literal["BUNDLED_BASELINE_ADOPTION", "DAILY_GLM"]
    input_request_sha256: Sha256
    source_snapshot_sha256: Sha256
    source_run_date: date
    result_sha256: Sha256


class MvpScoredProfileV2(StrictContract):
    profile: MvpScoredProfile
    lineage: DailyProfileLineage
    entry_sha256: Sha256

    @model_validator(mode="after")
    def validate_entry(self) -> Self:
        if self.lineage.origin == "DAILY_GLM" and (
            self.profile.scoring_result.request_sha256 != self.lineage.input_request_sha256
            or self.profile.scoring_result.result_sha256 != self.lineage.result_sha256
        ):
            raise ValueError("daily profile lineage does not match scoring result")
        if self.profile.scoring_result.result_sha256 != self.lineage.result_sha256:
            raise ValueError("profile result lineage does not match")
        expected = canonical_sha256(self.model_dump(exclude={"entry_sha256"}, mode="json"))
        if self.entry_sha256 != expected:
            raise ValueError("daily profile entry hash does not match")
        return self


class MvpScoredReleaseV2(StrictContract):
    schema_version: Literal["mvp-scored-release.v2"]
    authority_membership_sha256: Sha256
    published_count: Annotated[int, Field(strict=True, ge=80, le=100)]
    membership_sha256: Sha256
    relation_sha256: Sha256
    relation_pairs: tuple[tuple[PublicPlaceId, PublicPlaceId], ...]
    profile_entries: Annotated[tuple[MvpScoredProfileV2, ...], Field(min_length=80, max_length=100)]
    failed: Annotated[tuple[FailedPlace, ...], Field(max_length=20)]
    previous_release_sha256: Sha256
    daily_run_date: date
    snapshot_sha256: Sha256
    delta_sha256: Sha256
    authority_sha256: Sha256
    created_at: datetime
    release_sha256: Sha256

    @property
    def profiles(self) -> tuple[MvpScoredProfile, ...]:
        return tuple(row.profile for row in self.profile_entries)

    @model_validator(mode="after")
    def validate_release(self) -> Self:
        require_utc(self.created_at, field_name="created_at")
        if self.authority_membership_sha256 != DAILY_REFRESH_MEMBERSHIP_SHA256:
            raise ValueError("daily release authority membership does not match")
        if self.authority_sha256 != DAILY_REFRESH_AUTHORITY.authority_sha256:
            raise ValueError("daily release authority does not match")
        profiles = self.profiles
        profile_ids = tuple(row.place_id for row in profiles)
        failed_ids = tuple(row.place_id for row in self.failed)
        if profile_ids != tuple(sorted(profile_ids)) or len(profile_ids) != len(set(profile_ids)):
            raise ValueError("daily release profiles must use canonical order")
        if failed_ids != tuple(sorted(failed_ids)) or len(failed_ids) != len(set(failed_ids)):
            raise ValueError("daily release failures must use canonical order")
        if set(profile_ids).intersection(failed_ids) or len(profile_ids) + len(failed_ids) != 100:
            raise ValueError("daily release must cover PUBLIC-100 exactly")
        if self.published_count != len(profile_ids):
            raise ValueError("daily release published count does not match")
        if self.membership_sha256 != canonical_sha256(list(profile_ids)):
            raise ValueError("daily release membership hash does not match")
        pairs = tuple(self.relation_pairs)
        if pairs != tuple(sorted(pairs)) or len(pairs) != len(set(pairs)):
            raise ValueError("daily release relations must use canonical order")
        members = set(profile_ids)
        if any(
            left >= right or left not in members or right not in members for left, right in pairs
        ):
            raise ValueError("daily release relation endpoint is invalid")
        from itda.contracts.recommendation import public_relation_sha256

        if self.relation_sha256 != public_relation_sha256(profile_ids, pairs):
            raise ValueError("daily release relation hash does not match")
        expected = canonical_sha256(self.model_dump(exclude={"release_sha256"}, mode="json"))
        if self.release_sha256 != expected:
            raise ValueError("daily release hash does not match")
        return self


class DailyRefreshAuthorityV2(StrictContract):
    schema_version: Literal["mvp-daily-glm-refresh-authority.v2"]
    region: Literal["경주시"]
    pool: Literal["PUBLIC"]
    membership_sha256: Sha256
    tour_api_operations: tuple[Literal["detailCommon2"], Literal["detailIntro2"]]
    model: Literal["glm-5.3-flash"]
    endpoint: Literal["https://api.z.ai/api/coding/paas/v4/chat/completions"]
    prompt_sha256: Sha256
    timezone: Literal["Asia/Seoul"]
    local_hour: Literal[8]
    maximum_calls: Literal[200]
    concurrency: Literal[1]
    retry_limit_per_place: Literal[1]
    public_only: Literal[True]
    fallback: Literal[False]
    availability_states: tuple[
        Literal["AVAILABLE"], Literal["INFORMATION_UNAVAILABLE"], Literal["EVENT_ENDED"]
    ]
    normal_empty_codes: tuple[Literal["00"], Literal["0000"], Literal["03"]]
    event_end_timezone: Literal["Asia/Seoul"]
    minimum_published_profiles: Literal[80]
    authority_sha256: Sha256

    @model_validator(mode="after")
    def validate_authority(self) -> Self:
        if self.membership_sha256 != DAILY_REFRESH_MEMBERSHIP_SHA256:
            raise ValueError("daily availability membership does not match")
        if self.prompt_sha256 != MVP_SCORING_PROMPT_SHA256:
            raise ValueError("daily availability prompt does not match")
        _validate_hash(self, "authority_sha256")
        return self


def _validate_hash(model: StrictContract, field: str) -> None:
    if getattr(model, field) != canonical_sha256(model.model_dump(exclude={field}, mode="json")):
        raise ValueError("daily availability payload hash does not match")


_AUTHORITY_V2_FIELDS = {
    **_AUTHORITY_FIELDS,
    "schema_version": "mvp-daily-glm-refresh-authority.v2",
    "availability_states": ("AVAILABLE", "INFORMATION_UNAVAILABLE", "EVENT_ENDED"),
    "normal_empty_codes": ("00", "0000", "03"),
    "event_end_timezone": "Asia/Seoul",
    "minimum_published_profiles": 80,
}
DAILY_REFRESH_AUTHORITY_V2 = DailyRefreshAuthorityV2.model_validate(
    {**_AUTHORITY_V2_FIELDS, "authority_sha256": canonical_sha256(_AUTHORITY_V2_FIELDS)}
)


class DailyAvailabilityState(StrEnum):
    INFORMATION_UNAVAILABLE = "INFORMATION_UNAVAILABLE"
    EVENT_ENDED = "EVENT_ENDED"


class DailyProviderProvenance(StrictContract):
    operation: Literal["detailCommon2", "detailIntro2"]
    http_status: Annotated[int, Field(strict=True, ge=200, le=299)]
    response_sha256: Sha256
    retrieved_at: datetime

    @model_validator(mode="after")
    def validate_timestamp(self) -> Self:
        require_utc(self.retrieved_at, field_name="retrieved_at")
        return self


class DailyExcludedPlace(StrictContract):
    place_id: PublicPlaceId
    content_id: Annotated[str, Field(strict=True, pattern=r"^[0-9]{1,32}$")]
    content_type_id: Annotated[str, Field(strict=True, pattern=r"^[0-9]{1,2}$")]
    state: DailyAvailabilityState
    safe_reason: Literal["COMMON_INFORMATION_UNAVAILABLE", "OFFICIAL_EVENT_END_DATE_PASSED"]
    event_end_date: date | None
    permission_evidence_sha256: Sha256
    common: DailyProviderProvenance
    intro: DailyProviderProvenance | None
    row_sha256: Sha256

    @model_validator(mode="after")
    def validate_exclusion(self) -> Self:
        if self.common.operation != "detailCommon2":
            raise ValueError("excluded common provenance is invalid")
        if self.state == DailyAvailabilityState.INFORMATION_UNAVAILABLE:
            if (
                self.safe_reason != "COMMON_INFORMATION_UNAVAILABLE"
                or self.event_end_date is not None
                or self.intro is not None
            ):
                raise ValueError("unavailable place must not imply event closure")
        elif (
            self.safe_reason != "OFFICIAL_EVENT_END_DATE_PASSED"
            or self.content_type_id != "15"
            or self.event_end_date is None
            or self.intro is None
            or self.intro.operation != "detailIntro2"
        ):
            raise ValueError("ended event requires official dated intro provenance")
        _validate_hash(self, "row_sha256")
        return self

    @property
    def semantic_state(self) -> tuple[str, str, date | None]:
        return str(self.state), self.safe_reason, self.event_end_date


def _validate_partition(*groups: tuple[str, ...]) -> None:
    for ids in groups:
        if ids != tuple(sorted(set(ids))):
            raise ValueError("PUBLIC groups must be sorted and unique")
    ids = tuple(place_id for group in groups for place_id in group)
    if len(ids) != 100 or len(set(ids)) != 100:
        raise ValueError("availability must partition PUBLIC-100")
    if canonical_sha256(sorted(ids)) != DAILY_REFRESH_MEMBERSHIP_SHA256:
        raise ValueError("availability PUBLIC membership does not match")


class DailyScoringInputSnapshotV2(StrictContract):
    schema_version: Literal["mvp-daily-scoring-input-snapshot.v2"]
    run_date: date
    collected_at: datetime
    authority_sha256: Sha256
    membership_sha256: Sha256
    previous_snapshot_sha256: Sha256 | None
    places: Annotated[tuple[DailyPlaceInput, ...], Field(max_length=100)]
    excluded: Annotated[tuple[DailyExcludedPlace, ...], Field(max_length=100)]
    snapshot_sha256: Sha256

    @model_validator(mode="after")
    def validate_snapshot(self) -> Self:
        require_utc(self.collected_at, field_name="collected_at")
        _validate_partition(
            tuple(r.place_id for r in self.places), tuple(r.place_id for r in self.excluded)
        )
        if (
            self.authority_sha256 != DAILY_REFRESH_AUTHORITY_V2.authority_sha256
            or self.membership_sha256 != DAILY_REFRESH_MEMBERSHIP_SHA256
        ):
            raise ValueError("availability snapshot authority does not match")
        if any(
            r.event_end_date is not None and r.event_end_date >= self.run_date
            for r in self.excluded
        ):
            raise ValueError("event is not ended on the fixed run date")
        _validate_hash(self, "snapshot_sha256")
        return self


class DailyInputDeltaV2(StrictContract):
    schema_version: Literal["mvp-daily-input-delta.v2"]
    previous_snapshot_sha256: Sha256
    snapshot_sha256: Sha256
    changed_place_ids: tuple[PublicPlaceId, ...]
    unchanged_place_ids: tuple[PublicPlaceId, ...]
    delta_sha256: Sha256

    @model_validator(mode="after")
    def validate_delta(self) -> Self:
        _validate_partition(self.changed_place_ids, self.unchanged_place_ids)
        _validate_hash(self, "delta_sha256")
        return self


class DailyIncrementalScoringPlanV2(StrictContract):
    schema_version: Literal["mvp-daily-incremental-scoring-plan.v2"]
    run_date: date
    authority_sha256: Sha256
    snapshot_sha256: Sha256
    delta_sha256: Sha256
    endpoint: Literal["https://api.z.ai/api/coding/paas/v4/chat/completions"]
    model: Literal["glm-5.3-flash"]
    prompt_sha256: Sha256
    scoring_place_ids: Annotated[tuple[PublicPlaceId, ...], Field(min_length=1, max_length=100)]
    request_sha256: Annotated[tuple[Sha256, ...], Field(min_length=1, max_length=100)]
    first_pass_count: Annotated[int, Field(strict=True, ge=1, le=100)]
    retry_limit_per_place: Literal[1]
    maximum_calls: Literal[200]
    concurrency: Literal[1]
    fallback: Literal[False]
    pay_as_you_go_fallback: Literal[False]
    plan_sha256: Sha256

    @model_validator(mode="after")
    def validate_plan(self) -> Self:
        if self.scoring_place_ids != tuple(sorted(set(self.scoring_place_ids))):
            raise ValueError("scoring targets must be sorted and unique")
        if len(self.request_sha256) != len(self.scoring_place_ids) or (
            self.first_pass_count != len(self.scoring_place_ids)
        ):
            raise ValueError("scoring target bindings do not match")
        if (
            self.authority_sha256 != DAILY_REFRESH_AUTHORITY_V2.authority_sha256
            or self.prompt_sha256 != MVP_SCORING_PROMPT_SHA256
        ):
            raise ValueError("scoring plan authority does not match")
        _validate_hash(self, "plan_sha256")
        return self


class DailyBaselineObservation(StrictContract):
    snapshot_sha256: Sha256
    request_sha256: Sha256
    run_date: date


class MvpScoredProfileV3(StrictContract):
    profile: MvpScoredProfile
    lineage: DailyProfileLineage
    source_release_sha256: Sha256 | None
    baseline_observation: DailyBaselineObservation | None
    entry_sha256: Sha256

    @model_validator(mode="after")
    def validate_entry(self) -> Self:
        if (
            self.profile.scoring_result.request_sha256 != self.lineage.input_request_sha256
            or self.profile.scoring_result.result_sha256 != self.lineage.result_sha256
        ):
            raise ValueError("actual scoring provenance must remain unchanged")
        if self.lineage.origin == "BUNDLED_BASELINE_ADOPTION":
            if self.baseline_observation is None or self.source_release_sha256 is None:
                raise ValueError("bundled reuse requires a separate baseline observation")
        elif self.baseline_observation is not None:
            raise ValueError("daily scoring must not use a baseline observation")
        _validate_hash(self, "entry_sha256")
        return self


class DailyFailedPlaceV3(FailedPlace):
    input_request_sha256: Sha256
    source_snapshot_sha256: Sha256
    source_run_date: date
    origin: Literal["DAILY_GLM", "LEGACY_BASELINE_OBSERVATION"]


class MvpScoredReleaseV3(StrictContract):
    schema_version: Literal["mvp-scored-release.v3"]
    authority_membership_sha256: Sha256
    published_count: Annotated[int, Field(strict=True, ge=80, le=100)]
    membership_sha256: Sha256
    relation_sha256: Sha256
    relation_pairs: tuple[tuple[PublicPlaceId, PublicPlaceId], ...]
    profile_entries: Annotated[
        tuple[MvpScoredProfileV2 | MvpScoredProfileV3, ...], Field(min_length=80, max_length=100)
    ]
    failed: Annotated[tuple[DailyFailedPlaceV3, ...], Field(max_length=20)]
    excluded: Annotated[tuple[DailyExcludedPlace, ...], Field(max_length=20)]
    previous_release_sha256: Sha256
    daily_run_date: date
    snapshot_sha256: Sha256
    delta_sha256: Sha256
    authority_sha256: Sha256
    created_at: datetime
    release_sha256: Sha256

    @property
    def profiles(self) -> tuple[MvpScoredProfile, ...]:
        return tuple(row.profile for row in self.profile_entries)

    @model_validator(mode="after")
    def validate_release(self) -> Self:
        require_utc(self.created_at, field_name="created_at")
        ids = tuple(r.place_id for r in self.profiles)
        _validate_partition(
            ids, tuple(r.place_id for r in self.failed), tuple(r.place_id for r in self.excluded)
        )
        if (
            self.authority_sha256 != DAILY_REFRESH_AUTHORITY_V2.authority_sha256
            or self.authority_membership_sha256 != DAILY_REFRESH_MEMBERSHIP_SHA256
            or self.membership_sha256 != canonical_sha256(list(ids))
            or self.published_count != len(ids)
        ):
            raise ValueError("availability release authority does not match")
        if any(
            r.event_end_date is not None and r.event_end_date >= self.daily_run_date
            for r in self.excluded
        ):
            raise ValueError("release contains an event that has not ended")
        pairs = self.relation_pairs
        if pairs != tuple(sorted(set(pairs))) or any(
            left >= right or left not in ids or right not in ids for left, right in pairs
        ):
            raise ValueError("availability release relations are invalid")
        from itda.contracts.recommendation import public_relation_sha256

        if self.relation_sha256 != public_relation_sha256(ids, pairs):
            raise ValueError("availability release relation hash does not match")
        _validate_hash(self, "release_sha256")
        return self


DailySnapshot = DailyScoringInputSnapshot | DailyScoringInputSnapshotV2
DailyScoredRelease = MvpScoredRelease | MvpScoredReleaseV2 | MvpScoredReleaseV3


def parse_daily_snapshot(payload: object) -> DailySnapshot:
    if not isinstance(payload, dict):
        raise ValueError("daily snapshot payload must be an object")
    version = payload.get("schema_version")
    if version == "mvp-daily-scoring-input-snapshot.v1":
        return DailyScoringInputSnapshot.model_validate(payload)
    if version == "mvp-daily-scoring-input-snapshot.v2":
        return DailyScoringInputSnapshotV2.model_validate(payload)
    raise ValueError("unknown daily snapshot version")


def parse_daily_scored_release(payload: object) -> DailyScoredRelease:
    if not isinstance(payload, dict):
        raise ValueError("scored release payload must be an object")
    version = payload.get("schema_version")
    if version == "mvp-scored-release.v1":
        return MvpScoredRelease.model_validate(payload)
    if version == "mvp-scored-release.v2":
        return MvpScoredReleaseV2.model_validate(payload)
    if version == "mvp-scored-release.v3":
        return MvpScoredReleaseV3.model_validate(payload)
    raise ValueError("unknown scored release version")


class DailyRefreshStatusProjection(StrictContract):
    schema_version: Literal["mvp-daily-refresh-status.v1"] = "mvp-daily-refresh-status.v1"
    run_date: date | None
    status: DailyRefreshRunStatus | None
    changed_count: Annotated[int, Field(strict=True, ge=0, le=100)]
    failed_count: Annotated[int, Field(strict=True, ge=0, le=100)]
    call_count: Annotated[int, Field(strict=True, ge=0, le=200)]
    active_release_sha256: Sha256 | None
    next_run_at: datetime
    safe_reason: Annotated[str | None, Field(strict=True, pattern=r"^[A-Z0-9_]{1,80}$")] = None

    @model_validator(mode="after")
    def validate_next_run(self) -> Self:
        require_utc(self.next_run_at, field_name="next_run_at")
        return self


SafeReason = Annotated[str, Field(strict=True, pattern=r"^[A-Z0-9_]{1,80}$")]
CommandId = Annotated[
    str,
    Field(
        strict=True,
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    ),
]


class DailyRefreshExecutionKind(StrEnum):
    SCHEDULED = "SCHEDULED"
    MANUAL_RECOLLECTION = "MANUAL_RECOLLECTION"


class DailyCollectionOperation(StrEnum):
    DETAIL_COMMON = "detailCommon2"
    DETAIL_INTRO = "detailIntro2"


class DailyRecollectionCommandStatus(StrEnum):
    REQUESTED = "REQUESTED"
    CLAIMED = "CLAIMED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    REJECTED = "REJECTED"


class DailyCollectionFailure(StrictContract):
    schema_version: Literal["mvp-daily-collection-failure.v1"] = "mvp-daily-collection-failure.v1"
    place_id: PublicPlaceId
    operation: DailyCollectionOperation
    failure_category: SafeReason
    failure_code: SafeReason


class DailyCollectionFailureProjection(DailyCollectionFailure):
    execution_sequence: Annotated[int, Field(strict=True, ge=0, le=3)]
    occurred_at: datetime

    @model_validator(mode="after")
    def validate_occurred_at(self) -> Self:
        require_utc(self.occurred_at, field_name="occurred_at")
        return self


class DailyExcludedPlaceProjection(StrictContract):
    place_id: PublicPlaceId
    content_id: Annotated[str, Field(strict=True, pattern=r"^[0-9]{1,32}$")]
    state: DailyAvailabilityState
    safe_reason: Literal["COMMON_INFORMATION_UNAVAILABLE", "OFFICIAL_EVENT_END_DATE_PASSED"]
    event_end_date: date | None
    place_name_ko: Annotated[str | None, Field(strict=True, max_length=240)] = None


class DailyRefreshExecutionProjection(StrictContract):
    schema_version: Literal["mvp-daily-refresh-execution.v1"] = "mvp-daily-refresh-execution.v1"
    run_date: date
    execution_sequence: Annotated[int, Field(strict=True, ge=0, le=3)]
    kind: DailyRefreshExecutionKind
    command_id: CommandId | None
    authority_sha256: Sha256 | None = None
    snapshot_sha256: Sha256 | None = None
    available_count: Annotated[int | None, Field(strict=True, ge=0, le=100)] = None
    information_unavailable_count: Annotated[int | None, Field(strict=True, ge=0, le=100)] = None
    event_ended_count: Annotated[int | None, Field(strict=True, ge=0, le=100)] = None
    status: DailyRefreshRunStatus
    changed_count: Annotated[int, Field(strict=True, ge=0, le=100)]
    failed_count: Annotated[int, Field(strict=True, ge=0, le=100)]
    call_count: Annotated[int, Field(strict=True, ge=0, le=200)]
    active_release_sha256: Sha256 | None
    safe_reason: SafeReason | None
    started_at: datetime
    updated_at: datetime
    finished_at: datetime | None

    @model_validator(mode="after")
    def validate_timestamps(self) -> Self:
        require_utc(self.started_at, field_name="started_at")
        require_utc(self.updated_at, field_name="updated_at")
        if self.finished_at is not None:
            require_utc(self.finished_at, field_name="finished_at")
        counts = (self.available_count, self.information_unavailable_count, self.event_ended_count)
        known = tuple(value for value in counts if value is not None)
        if known and (len(known) != 3 or sum(known) != 100):
            raise ValueError("availability counts must be all unknown or partition PUBLIC-100")
        if self.kind == DailyRefreshExecutionKind.SCHEDULED and self.command_id is not None:
            raise ValueError("scheduled execution must not reference a command")
        if self.kind == DailyRefreshExecutionKind.MANUAL_RECOLLECTION and self.command_id is None:
            raise ValueError("manual recollection must reference a command")
        return self


class DailyGlmAttemptProjection(StrictContract):
    schema_version: Literal["mvp-daily-glm-attempt-projection.v1"] = (
        "mvp-daily-glm-attempt-projection.v1"
    )
    run_date: date
    execution_sequence: Annotated[int, Field(strict=True, ge=0, le=3)]
    place_id: PublicPlaceId
    attempt_number: Literal[1, 2]
    status: Literal["STARTED", "SUCCEEDED", "FAILED"]
    safe_reason: SafeReason | None
    result_sha256: Sha256 | None
    reserved_at: datetime
    finished_at: datetime | None

    @model_validator(mode="after")
    def validate_attempt(self) -> Self:
        require_utc(self.reserved_at, field_name="reserved_at")
        if self.finished_at is not None:
            require_utc(self.finished_at, field_name="finished_at")
        if self.status == "STARTED" and (
            self.safe_reason is not None
            or self.result_sha256 is not None
            or self.finished_at is not None
        ):
            raise ValueError("started attempt must not contain terminal fields")
        if self.status == "SUCCEEDED" and (
            self.safe_reason is not None or self.result_sha256 is None or self.finished_at is None
        ):
            raise ValueError("successful attempt projection is incomplete")
        if self.status == "FAILED" and (
            self.safe_reason is None or self.result_sha256 is not None or self.finished_at is None
        ):
            raise ValueError("failed attempt projection is incomplete")
        return self


class DailyRecollectionEligibility(StrictContract):
    eligible: bool
    safe_reason: SafeReason


class DailyRecollectionCommandRequest(StrictContract):
    schema_version: Literal["mvp-daily-recollection-command-request.v1"] = (
        "mvp-daily-recollection-command-request.v1"
    )
    run_date: date
    idempotency_key: Annotated[
        str,
        Field(strict=True, pattern=r"^[A-Za-z0-9_-]{16,128}$"),
    ]


class DailyRecollectionCommandProjection(StrictContract):
    schema_version: Literal["mvp-daily-recollection-command.v1"] = (
        "mvp-daily-recollection-command.v1"
    )
    command_id: CommandId
    run_date: date
    idempotency_key: Annotated[
        str,
        Field(strict=True, pattern=r"^[A-Za-z0-9_-]{16,128}$"),
    ]
    status: DailyRecollectionCommandStatus
    execution_sequence: Annotated[int | None, Field(strict=True, ge=1, le=3)]
    safe_reason: SafeReason | None
    requested_at: datetime
    claimed_at: datetime | None
    lease_expires_at: datetime | None
    finished_at: datetime | None

    @model_validator(mode="after")
    def validate_command(self) -> Self:
        for field_name in (
            "requested_at",
            "claimed_at",
            "lease_expires_at",
            "finished_at",
        ):
            value = getattr(self, field_name)
            if value is not None:
                require_utc(value, field_name=field_name)
        if self.status == DailyRecollectionCommandStatus.REQUESTED and any(
            value is not None
            for value in (
                self.execution_sequence,
                self.claimed_at,
                self.lease_expires_at,
                self.finished_at,
            )
        ):
            raise ValueError("requested command must not contain processing fields")
        if self.status == DailyRecollectionCommandStatus.CLAIMED and (
            self.execution_sequence is None
            or self.claimed_at is None
            or self.lease_expires_at is None
            or self.finished_at is not None
        ):
            raise ValueError("claimed command projection is incomplete")
        if (
            self.status
            in {
                DailyRecollectionCommandStatus.SUCCEEDED,
                DailyRecollectionCommandStatus.FAILED,
                DailyRecollectionCommandStatus.REJECTED,
            }
            and self.finished_at is None
        ):
            raise ValueError("terminal command requires finished_at")
        return self


class DailyGlmOperationsOverview(StrictContract):
    schema_version: Literal["mvp-daily-glm-operations-overview.v1"] = (
        "mvp-daily-glm-operations-overview.v1"
    )
    latest_execution: DailyRefreshExecutionProjection | None
    next_run_at: datetime
    active_release_sha256: Sha256 | None
    recollection: DailyRecollectionEligibility
    pending_command: DailyRecollectionCommandProjection | None

    @model_validator(mode="after")
    def validate_next_run(self) -> Self:
        require_utc(self.next_run_at, field_name="next_run_at")
        return self


class DailyGlmExecutionHistory(StrictContract):
    schema_version: Literal["mvp-daily-glm-execution-history.v1"] = (
        "mvp-daily-glm-execution-history.v1"
    )
    days: Annotated[int, Field(strict=True, ge=1, le=30)]
    executions: Annotated[tuple[DailyRefreshExecutionProjection, ...], Field(max_length=120)]


class DailyGlmExecutionDetail(StrictContract):
    schema_version: Literal["mvp-daily-glm-execution-detail.v1"] = (
        "mvp-daily-glm-execution-detail.v1"
    )
    execution: DailyRefreshExecutionProjection
    collection_failures: Annotated[
        tuple[DailyCollectionFailureProjection, ...], Field(max_length=100)
    ]
    attempts: Annotated[tuple[DailyGlmAttemptProjection, ...], Field(max_length=200)]
    excluded: Annotated[tuple[DailyExcludedPlaceProjection, ...] | None, Field(max_length=100)] = (
        None
    )
