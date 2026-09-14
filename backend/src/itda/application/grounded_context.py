"""Pure reconstruction of v5 inputs from an immutable complete pair and source pins."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import date, datetime
from functools import partial
from typing import Any, cast

from itda.contracts.grounded_recommendation import GroundedTripInput
from itda.contracts.grounded_release import GroundedReleaseCandidate
from itda.contracts.grounded_run import CONDITION_KEYS, GroundedPreference
from itda.contracts.grounded_source import GroundedSourceProfile
from itda.contracts.mvp_scored_release import MvpScoredProfile
from itda.contracts.place_enrichment import CampingContext
from itda.contracts.place_facts import FactSource
from itda.contracts.preference import PreferenceProfile
from itda.contracts.source_assessment import ClaimKind, SourceObservation, SupportState
from itda.contracts.visual_mood import ConfirmedMoodProjection, VisualMoodDimension
from itda.domain.canonical import canonical_sha256
from itda.domain.grounded_recommendation import GroundedCandidate
from itda.domain.recommendation_projection import project_recommendation_preference
from itda.domain.visual_mood import aggregate_moods
from itda.pipeline.destination_evidence import DestinationEvidenceSnapshot
from itda.pipeline.place_facts import extract_place_facts
from itda.tourism.accessibility import AccessibilitySnapshot, facility_observations, provider_items
from itda.tourism.camping import CampingEnrichmentService
from itda.tourism.temporal import TemporalContextService
from itda.tourism.temporal_cache import TemporalSourceSnapshot


class _PinnedBatchLoader:
    """The collector seam backed only by a validated immutable source batch."""

    def __init__(self, snapshot: TemporalSourceSnapshot) -> None:
        self.snapshot = snapshot

    def collect_source_batch(
        self, service: object, operation: str, params: object, client: object
    ) -> TemporalSourceSnapshot:
        if service != self.snapshot.service or operation != self.snapshot.operation or params != {}:
            raise ValueError("pinned source does not match the requested collector operation")
        return self.snapshot


def _camp_time(camp: CampingContext) -> datetime:
    return camp.retrieved_at


def preference_submission_sha256(profile: PreferenceProfile) -> str:
    return canonical_sha256(
        {
            "questionnaire_version": profile.questionnaire_version,
            "scoring_version": profile.scoring_version,
            "description_template_version": profile.description_template_version,
            "config_hash": profile.config_hash,
            "trip_conditions": profile.trip_conditions.model_dump(mode="json"),
            "answers": profile.answers.model_dump(mode="json"),
        }
    )


def build_grounded_preference(
    profile: PreferenceProfile, request: Any, confirmed_mood: ConfirmedMoodProjection | None
) -> GroundedPreference:
    if profile.profile_id != request.preference_profile_id:
        raise ValueError("preference profile ownership differs")
    # Reuse only the quiz's declared axes/traits. Images never rewrite them.
    from itda.contracts.recommendation import RecommendationPurpose, RecommendationQualityContext

    quality = RecommendationQualityContext(
        companion=profile.trip_conditions.companion.value,
        transport=profile.trip_conditions.transport.value,
        purpose=request.purpose or RecommendationPurpose.SIGHTSEEING,
        eligible_place_ids=(),
    )
    quiz = project_recommendation_preference(profile, quality_context=quality)
    trip = request.grounded_input or GroundedTripInput(
        visit_date=profile.trip_conditions.visit_date
    )
    if (confirmed_mood is None) != (request.photo_job_id is None):
        raise ValueError("photo input needs an immutable confirmed mood receipt")
    if confirmed_mood is not None:
        confirmed_mood = ConfirmedMoodProjection.model_validate_json(
            confirmed_mood.model_dump_json()
        )
        if (
            confirmed_mood.job_id != request.photo_job_id
            or confirmed_mood.preference_profile_id != profile.profile_id
        ):
            raise ValueError("confirmed mood ownership differs")
    targets = {c.condition_id.value: c.value for c in quiz.condition_targets}
    targets["COMPANIONS"] = (
        None  # Facility needs are explicit; companion never infers mobility needs.
    )
    targets["VISIT_DATE_TIME"] = 100 if trip.visit_time is not None else None
    targets["WALKING"] = 100  # A tolerance is a feasibility ceiling, not desire for a long walk.
    targets["CROWD"] = None  # No physical density observations in the configured KTO source set.
    return GroundedPreference(
        profile_id=profile.profile_id,
        input_sha256=preference_submission_sha256(profile),
        trip_input=trip,
        purpose=quality.purpose.value,
        axis_targets={key: row.value for key, row in zip("HER", quiz.axis_targets, strict=True)},
        trait_targets={row.trait_id.value: row.value for row in quiz.trait_targets},
        important_traits=tuple(
            sorted(row.trait_id.value for row in quiz.trait_targets if row.important)
        ),
        condition_targets=targets,
        mood_targets={
            d.value: next((m.value for m in confirmed_mood.moods if m.dimension == d), None)
            if confirmed_mood
            else None
            for d in VisualMoodDimension
        },
        photo_input_sha256=confirmed_mood.receipt_id if confirmed_mood else None,
    )


def _unknown(key: str, reason: str, claim: ClaimKind = ClaimKind.FACILITY) -> SourceObservation:
    return SourceObservation(
        key=key,
        claim=claim,
        state=SupportState.UNKNOWN,
        value=None,
        evidence=(),
        reference_date=None,
        reason=reason,
    )


def _merge_facilities(
    groups: Sequence[Mapping[str, SourceObservation]],
) -> dict[str, SourceObservation]:
    keys = {
        key for group in groups for key, row in group.items() if row.claim == ClaimKind.FACILITY
    }
    result = {}
    for key in keys:
        rows = [
            g[key]
            for g in groups
            if key in g
            and g[key].state == SupportState.FACT
            and g[key].claim == ClaimKind.FACILITY
            and type(g[key].value) is bool
        ]
        values = {r.value for r in rows}
        if len(values) != 1:
            result[key] = _unknown(
                key, "공식 정보가 서로 다릅니다." if values else "명시적인 시설 정보가 없습니다."
            )
        else:
            evidence = {e.evidence_id: e for row in rows for e in row.evidence}
            result[key] = SourceObservation(
                key=key,
                claim=ClaimKind.FACILITY,
                state=SupportState.FACT,
                value=rows[0].value,
                evidence=tuple(evidence[e] for e in sorted(evidence)),
                reference_date=min(r.reference_date for r in rows if r.reference_date is not None),
                reason="동일한 공식 시설 정보만 사용합니다. 현재 현장 상태와 다를 수 있습니다.",
            )
    return result


def _source_conditions(
    assessment: Any,
    source: DestinationEvidenceSnapshot,
    preference: GroundedPreference,
    user: PreferenceProfile,
) -> dict[str, SourceObservation]:
    result = {
        k: _unknown(
            k,
            "해당 조건의 검증된 장소 정보가 없습니다.",
            ClaimKind.CROWD if k == "CROWD" else ClaimKind.EXPERIENCE,
        )
        for k in CONDITION_KEYS
    }
    official_evidence = {
        e.evidence_id: e
        for e in source.evidence
        if e.receipt.service == "KorService2"
        and e.modality != "IMAGE_PIXELS"
        and (e.authorizes(ClaimKind.FACILITY) or e.authorizes(ClaimKind.OPERATING))
    }
    fact_evidence = {
        f"evidence:{canonical_sha256(key)}": e
        for key, e in official_evidence.items()
        if len(f"TourAPI {e.source_field}: {e.excerpt}") <= 4000
    }
    facts = extract_place_facts(
        source.place.place_id,
        tuple(
            FactSource(
                place_id=source.place.place_id,
                evidence_id=fact_id,
                provider="TOUR_API",
                provider_source_id=e.place_match.provider_entity_id
                if e.place_match and e.place_match.provider_entity_id
                else source.place.place_id,
                excerpt=f"TourAPI {e.source_field}: {e.excerpt}",
                reference_date=e.receipt.reference_date or e.receipt.retrieved_at.date(),
                source_response_sha256=cast(str, e.receipt.response_sha256),
            )
            for fact_id, e in fact_evidence.items()
        ),
    )

    def from_fact(target_key: str, fact_key: str, value: int) -> None:
        fact = facts.observations[fact_key]
        evidence = tuple(fact_evidence[e.source.evidence_id] for e in fact.evidence)
        result[target_key] = SourceObservation(
            key=target_key,
            claim=ClaimKind.FACILITY,
            state=SupportState.FACT,
            value=value,
            evidence=evidence,
            reference_date=min(e.source.reference_date for e in fact.evidence),
            reason="명시된 공식 사실을 여행 조건에 맞춰 비교했습니다.",
        )

    walking = facts.observations["walking_minutes"]
    if walking.state == "FACT" and type(walking.value) is int:
        limit = {"WITHIN_30_MINUTES": 30, "ABOUT_1_HOUR": 60, "EXTENDED_WALKING_OK": 720}[
            user.trip_conditions.walking_tolerance.value
        ]
        from_fact("WALKING", "walking_minutes", 100 if walking.value <= limit else 0)
    transit = facts.observations["transit_access"]
    if (
        user.trip_conditions.transport.value == "WALK_OR_TRANSIT"
        and transit.state == "FACT"
        and type(transit.value) is bool
    ):
        from_fact("TRANSPORT", "transit_access", 100 if transit.value else 0)

    def converted(key: str, row: SourceObservation, value: int) -> None:
        result[key] = SourceObservation(
            key=key,
            claim=row.claim,
            state=row.state,
            value=value,
            evidence=row.evidence,
            reference_date=row.reference_date,
            reason="등록된 사실과 조건을 비교했습니다. 현장 상태의 실시간 확인이 아닙니다.",
        )

    parking = assessment.facts.get("tour_parking")
    if (
        user.trip_conditions.transport.value == "CAR_OR_TAXI"
        and parking is not None
        and isinstance(parking.value, str)
    ):
        compact = re.sub(r"\s+", "", parking.value)
        if re.fullmatch(r"(?:주차)?(?:가능|가능함|가능합니다)", compact):
            converted("TRANSPORT", parking, 100)
        elif re.fullmatch(r"(?:주차)?(?:불가|불가능|없음)", compact):
            converted("TRANSPORT", parking, 0)
    # Only exact, complete numeric schedule strings; no weekday/year-round or open-now inference.
    if preference.trip_input.visit_time is not None:
        schedules = [
            r
            for k, r in assessment.facts.items()
            if k.startswith(("tour_usetime", "tour_opentime")) and isinstance(r.value, str)
        ]
        outcomes = []
        hh, mm = map(int, preference.trip_input.visit_time.split(":"))
        target = hh * 60 + mm
        for row in schedules:
            match = re.fullmatch(
                r"\s*([01]?\d|2[0-3]):([0-5]\d)\s*[~∼-]\s*([01]?\d|2[0-3]):([0-5]\d)\s*",
                str(row.value),
            )
            if match:
                a, b, c, d = map(int, match.groups())
                start = a * 60 + b
                end = c * 60 + d
                if start < end:
                    outcomes.append((100 if start <= target < end else 0, row))
        if outcomes and len({v for v, _ in outcomes}) == 1:
            converted("VISIT_DATE_TIME", outcomes[0][1], outcomes[0][0])
    # Exact source prose can establish indoor/outdoor context; images and regional records cannot.
    for evidence in source.evidence:
        if evidence.modality == "IMAGE_PIXELS" or not evidence.authorizes(ClaimKind.EXPERIENCE):
            continue
        match = re.fullmatch(
            r"\s*(실내|야외|실외)\s*(?:전시관|공간|시설)(?:입니다|임|이다)?[.]?\s*",
            evidence.excerpt,
        )
        if match:
            result["INDOOR_OUTDOOR"] = SourceObservation(
                key="INDOOR_OUTDOOR",
                claim=ClaimKind.EXPERIENCE,
                state=SupportState.FACT,
                value=0 if match[1] == "실내" else 100,
                evidence=(evidence,),
                reference_date=evidence.receipt.reference_date
                or evidence.receipt.retrieved_at.date(),
                reason="공식 문구의 실내·실외 구분입니다.",
            )
    return result


def _season(day: date | None) -> str | None:
    if day is None:
        return None
    return (
        "SPRING"
        if day.month in (3, 4, 5)
        else "SUMMER"
        if day.month in (6, 7, 8)
        else "AUTUMN"
        if day.month in (9, 10, 11)
        else "WINTER"
    )


def build_candidates(
    candidate: GroundedReleaseCandidate,
    contextual_payloads: Sequence[Mapping[str, Any]],
    preference: GroundedPreference,
    user_profile: PreferenceProfile,
) -> tuple[GroundedCandidate, ...]:
    if preference.input_sha256 != preference_submission_sha256(user_profile):
        raise ValueError("grounded reconstruction needs the exact original user profile")
    sources = {
        s.place.place_id: s
        for s in (DestinationEvidenceSnapshot.model_validate(p) for p in candidate.source_snapshots)
    }
    access: list[AccessibilitySnapshot] = []
    camps: list[CampingContext] = []
    temporal: dict[str, TemporalSourceSnapshot] = {}
    for payload in contextual_payloads:
        version = payload.get("schema_version")
        if version == "accessibility-snapshot.v1":
            snapshot = AccessibilitySnapshot.model_validate(payload)
            if snapshot.match.state == "MATCHED":
                receipt = next(
                    (
                        r
                        for r in snapshot.receipts
                        if r.operation == "detailWithTour2" and r.status == "AVAILABLE"
                    ),
                    None,
                )
                if receipt is not None:
                    raw_response = next(
                        (
                            r
                            for r in snapshot.raw_responses
                            if r.get("raw_response_sha256") == receipt.response_sha256
                        ),
                        None,
                    )
                    rows = provider_items(raw_response["payload"]) if raw_response else ()
                    rows = tuple(
                        r
                        for r in rows
                        if str(r.get("contentid")) == snapshot.match.provider_entity_id
                    )
                    if (
                        len(rows) != 1
                        or facility_observations(rows[0], receipt, snapshot.match) != snapshot.facts
                    ):
                        raise ValueError(
                            "facility assertions differ from the original official fields"
                        )
            access.append(snapshot)
        elif version == "camping-context.v1":
            camps.append(CampingContext.model_validate(payload))
        elif version == "temporal-source-snapshot.v1":
            temporal[canonical_sha256(payload)] = TemporalSourceSnapshot.model_validate(payload)
        else:
            raise ValueError("unsupported contextual snapshot schema")
    for camp in camps:
        if any(h not in temporal for h in camp.source_snapshot_sha256):
            raise ValueError("camp context requires its raw official source batch")
        if camp.place_id not in sources or len(camp.source_snapshot_sha256) != 1:
            raise ValueError("camp context place/source identity differs")
        batch = temporal[camp.source_snapshot_sha256[0]]
        rebuilt = CampingEnrichmentService(
            places=(sources[camp.place_id].place,),
            client=None,
            loader=cast(TemporalContextService, _PinnedBatchLoader(batch)),
            clock=partial(_camp_time, camp),
        ).get_context(camp.place_id)
        if (
            rebuilt.match.state != camp.match.state
            or rebuilt.match.provider_entity_id != camp.match.provider_entity_id
        ):
            raise ValueError("camp context match differs from official rows")
        for key, camp_fact in camp.facts.items():
            if camp_fact.state != SupportState.UNKNOWN:
                expected = rebuilt.facts.get(key)
                if (
                    expected is None
                    or expected.state != camp_fact.state
                    or expected.value != camp_fact.value
                    or expected.claim != camp_fact.claim
                    or expected.evidence != camp_fact.evidence
                ):
                    raise ValueError("camp facility assertions differ from their official source")
    ids = {p.place_id for p in candidate.raw_release.profiles}
    contexts: tuple[AccessibilitySnapshot | CampingContext, ...] = (*access, *camps)
    if any(s.place_id not in ids for s in contexts):
        raise ValueError("contextual place is outside the immutable candidate membership")
    desired_season = _season(preference.trip_input.visit_date)
    exact_time = preference.trip_input.visit_time
    period = user_profile.trip_conditions.visit_time.value
    desired_light = (
        ("NIGHT" if int(exact_time[:2]) >= 19 or int(exact_time[:2]) < 6 else "DAY")
        if exact_time
        else "NIGHT"
        if period == "EVENING"
        else "DAY"
        if period in ("MORNING", "DAYTIME")
        else None
    )
    result = []
    for raw, assessment, mood in zip(
        cast(Sequence[MvpScoredProfile | GroundedSourceProfile], candidate.raw_release.profiles),
        candidate.assessments,
        candidate.moods,
        strict=True,
    ):
        selected = tuple(
            i
            for i in mood.images
            if (desired_season is None or i.season in ("UNKNOWN", desired_season))
            and (desired_light is None or i.light_context in ("UNKNOWN", desired_light))
        )
        projected = aggregate_moods(tuple(i.candidate_set for i in selected))
        mood_observations = {}
        for row in projected:
            if row.value is None:
                continue
            images = [
                i
                for i in selected
                if any(c.candidate_id in row.candidate_ids for c in i.candidate_set.candidates)
            ]
            evidence = tuple(i.evidence for i in images)
            mood_observations[row.dimension.value] = SourceObservation(
                key=row.dimension.value,
                claim=ClaimKind.VISUAL_MOOD,
                state=SupportState.INFERENCE,
                value=row.value,
                evidence=evidence,
                reference_date=min(
                    (
                        i.capture_date
                        or i.evidence.receipt.reference_date
                        or i.evidence.receipt.retrieved_at.date()
                    )
                    for i in images
                ),
                reason="선택 시기·시간의 사진 분위기만 비교합니다. 현재 모습은 미확인입니다.",
            )
        facility_groups = [
            assessment.facts,
            *[s.facts for s in contexts if s.place_id == raw.place_id],
        ]
        result.append(
            GroundedCandidate(
                profile=raw,
                assessment=assessment,
                category=sources[raw.place_id].category,
                region_code=sources[raw.place_id].place.region_code
                if sources[raw.place_id].place.region_name is not None
                else None,
                region_name=sources[raw.place_id].place.region_name,
                address_ko=(sources[raw.place_id].place.address or None)
                if sources[raw.place_id].place.region_name is not None
                else None,
                conditions=_source_conditions(
                    assessment, sources[raw.place_id], preference, user_profile
                ),
                moods=mood_observations,
                contextual_facts=_merge_facilities(facility_groups),
            )
        )
    return tuple(result)
