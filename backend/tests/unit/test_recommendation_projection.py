"""Golden behavior for the Phase 5 recommendation projection policy."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from itda.application.recommendations import (
    _recommendation_candidates,
    _recommendation_preference,
)
from itda.contracts.demo_profile_materialization import (
    PublicScoredProfile,
    PublicScoredReleaseSnapshot,
)
from itda.contracts.preference import (
    CompanionType,
    CrowdAvoidance,
    IndoorOutdoorPreference,
    QuestionnaireSubmission,
    TransportType,
    VisitTime,
    WalkingTolerance,
)
from itda.contracts.recommendation import TravelConditionId
from itda.domain.preference import calculate_preference
from itda.domain.recommendation_projection import (
    RECOMMENDATION_PROJECTION_VERSION,
    project_traveler_trait_targets,
)

CREATED_AT = datetime(2026, 8, 10, 14, 0, tzinfo=UTC)


def _profile():
    return calculate_preference(
        QuestionnaireSubmission.model_validate(
            {
                "request_id": "anonymous:projection-profile",
                "trip_conditions": {
                    "visit_date": "2026-10-09",
                    "visit_time": "EVENING",
                    "companion": "FAMILY_WITH_CHILDREN",
                    "transport": "CAR_OR_TAXI",
                    "walking_tolerance": "EXTENDED_WALKING_OK",
                    "indoor_outdoor_preference": "OUTDOOR",
                    "crowd_avoidance": "HIGH",
                },
                "answers": {
                    "q1": 2,
                    "q2": 3,
                    "q3": 2,
                    "q4": 3,
                    "q5": 2,
                    "q6": 3,
                    "q7": 3,
                    "q8": 1,
                    "q9": 1,
                    "q10": 2,
                    "q11": 2,
                    "q12": 2,
                },
            }
        ),
        created_at=CREATED_AT,
    )


def _public_profile(index: int) -> PublicScoredProfile:
    evidence_id = f"evidence:projection:{index:02d}"
    evidence_ids = (evidence_id,)
    justifications = {
        key: evidence_ids
        for key in (
            "H",
            "E",
            "R",
            "H1",
            "H2",
            "H3",
            "H4",
            "I1",
            "I2",
            "I3",
            "I4",
            "R1",
            "R2",
            "R3",
            "R4",
            "M1",
            "M2",
            "M3",
            "M4",
            "M5",
            "M6",
        )
    }
    from itda.contracts.demo_profile_materialization import PublicEvidenceExcerpt

    evidence = PublicEvidenceExcerpt.model_construct(
        evidence_id=evidence_id,
        source_kind="TOURAPI_DESCRIPTION",
        source_label_ko="관광지 설명",
        attribution_ko="한국관광공사",
        provider="tourapi",
        official_dataset_id="15101971",
        endpoint="https://example.test/tourapi",
        contest_use_scope="noncommercial_contest_demo_evaluation",
        contest_rights_qualified=True,
        commercial_production_rights_review_required=True,
        excerpt_ko="경주의 역사와 풍경을 함께 살펴볼 수 있는 검증용 근거 문장입니다.",
        excerpt_sha256="a" * 64,
        source_sha256="b" * 64,
        span_sha256="c" * 64,
        source_authority_sha256="d" * 64,
        contest_rights_root_sha256="e" * 64,
    )
    return PublicScoredProfile.model_construct(
        place_id=f"place:projection:{index:02d}",
        place_name_ko=f"검증 장소 {index}",
        duplicate_group_id=f"hard-duplicate-singleton:{index:064x}",
        axis_scores={"H": 61, "E": 42, "R": 77},
        subattributes={
            **{f"H{number}": 1 for number in range(1, 5)},
            **{f"I{number}": 2 for number in range(1, 5)},
            "R1": 3,
            "R2": 1,
            "R3": 2,
            "R4": 1,
        },
        mismatch_traits={"M1": 11, "M2": 22, "M3": 28, "M4": 44, "M5": 63, "M6": 32},
        evidence_ids=evidence_ids,
        evidence_justifications=justifications,
        evidence_excerpts=(evidence,),
        confidence=80,
        publishable=True,
        publication_state="PUBLISHABLE",
        recommendation_eligible=True,
        analysis_origin="DEMO_MODEL_DERIVED",
        model="minimaxai/minimax-m3",
        prompt_version="phase5-demo-profile-sentinel-json.v5",
        profile_sha256=f"{index + 10:064x}",
        source_bundle_sha256="f" * 64,
        evidence_inventory_sha256="1" * 64,
        response_sha256="2" * 64,
        created_at=CREATED_AT,
        projection_sha256=f"{index + 20:064x}",
    )


def test_real_profile_and_scored_place_use_typed_non_neutral_projection() -> None:
    profile = _profile()
    preference = _recommendation_preference(profile)

    assert tuple(row.value for row in preference.condition_targets) == (
        100,
        75,
        100,
        100,
        100,
        100,
    )
    # v2 choice projection: axis shares H=33, E=60, R=18 from the reviewed
    # matrix normalized against each axis's attainable bounds, then the same
    # six-target composition: M1 M2 M3 M4 M5 M6. Importance flags follow the
    # v2 extremes: H=33/E=60 stay below the 75 threshold; crowd HIGH, rest
    # walking flag, and evening+E>=50 stay marked.
    assert tuple(row.value for row in preference.trait_targets) == (64, 67, 100, 40, 45, 80)
    assert tuple(row.important for row in preference.trait_targets) == (
        False,
        False,
        True,
        False,
        True,
        True,
    )

    snapshot = PublicScoredReleaseSnapshot.model_construct(
        profiles=tuple(_public_profile(index) for index in range(1, 6))
    )
    candidates = _recommendation_candidates(snapshot)
    first = candidates[0]
    assert tuple(row.condition_id for row in first.condition_scores) == tuple(TravelConditionId)
    assert tuple(row.value for row in first.condition_scores) == (32, 44, 37, 63, 75, 72)
    assert all(row.evidence_ids == ("evidence:projection:01",) for row in first.condition_scores)


@pytest.mark.parametrize(
    ("field_name", "condition_id", "values"),
    [
        (
            "visit_time",
            TravelConditionId.VISIT_DATE_TIME,
            (
                (VisitTime.UNDECIDED, 0),
                (VisitTime.MORNING, 50),
                (VisitTime.DAYTIME, 50),
                (VisitTime.SUNSET, 100),
                (VisitTime.EVENING, 100),
            ),
        ),
        (
            "companion",
            TravelConditionId.COMPANIONS,
            (
                (CompanionType.SOLO, 0),
                (CompanionType.FRIEND_OR_PARTNER, 25),
                (CompanionType.WITH_SENIORS, 25),
                (CompanionType.FAMILY_WITH_CHILDREN, 75),
                (CompanionType.GROUP, 100),
            ),
        ),
        (
            "transport",
            TravelConditionId.TRANSPORT,
            (
                (TransportType.WALK_OR_TRANSIT, 0),
                (TransportType.MIXED, 50),
                (TransportType.CAR_OR_TAXI, 100),
            ),
        ),
        (
            "walking_tolerance",
            TravelConditionId.WALKING,
            (
                (WalkingTolerance.WITHIN_30_MINUTES, 0),
                (WalkingTolerance.ABOUT_1_HOUR, 50),
                (WalkingTolerance.EXTENDED_WALKING_OK, 100),
            ),
        ),
        (
            "indoor_outdoor_preference",
            TravelConditionId.INDOOR_OUTDOOR,
            (
                (IndoorOutdoorPreference.INDOOR, 0),
                (IndoorOutdoorPreference.NO_PREFERENCE, 50),
                (IndoorOutdoorPreference.OUTDOOR, 100),
            ),
        ),
        (
            "crowd_avoidance",
            TravelConditionId.CROWD,
            ((CrowdAvoidance.LOW, 0), (CrowdAvoidance.MEDIUM, 50), (CrowdAvoidance.HIGH, 100)),
        ),
    ],
)
def test_every_trip_condition_enum_has_exact_target(
    field_name: str,
    condition_id: TravelConditionId,
    values: tuple[tuple[object, int], ...],
) -> None:
    from itda.domain.recommendation_projection import project_traveler_condition_targets

    baseline = _profile()
    for selected, expected in values:
        conditions = baseline.trip_conditions.model_copy(update={field_name: selected})
        targets = project_traveler_condition_targets(conditions)
        by_id = {row.condition_id: row.value for row in targets}
        assert by_id[condition_id] == expected


@pytest.mark.parametrize(
    ("answer_name", "trait_id", "expected_values"),
    [
        ("q4", "M1", (75, 63, 50, 38, 25)),
        ("q8", "M1", (0, 13, 25, 38, 50)),
        ("q7", "M2", (100, 75, 50, 25, 0)),
        ("q6", "M5", (33, 42, 50, 58, 67)),
        ("q9", "M5", (33, 42, 50, 58, 67)),
        ("q2", "M6", (0, 13, 25, 38, 50)),
    ],
)
def test_each_owned_answer_has_exact_half_up_boundary_values(
    answer_name: str,
    trait_id: str,
    expected_values: tuple[int, ...],
) -> None:
    from itda.contracts.preference import QuestionnaireAnswersV1

    baseline = _profile()
    conditions = baseline.trip_conditions
    if answer_name in {"q6", "q9"}:
        conditions = conditions.model_copy(
            update={"walking_tolerance": WalkingTolerance.ABOUT_1_HOUR}
        )
    if answer_name == "q2":
        conditions = conditions.model_copy(update={"visit_time": VisitTime.UNDECIDED})
    for answer, expected in zip(range(1, 6), expected_values, strict=True):
        # Legacy defaults mirror the original fixture: q4=5 pins M1's
        # (100 - norm_q4) term at 0; q6/q9 sit mid-scale for M5.
        answer_updates = {"q4": 5, "q6": 3, "q9": 3}
        answer_updates[answer_name] = answer
        answers = QuestionnaireAnswersV1.model_validate(
            {f"q{n}": 3 for n in range(1, 10)} | answer_updates
        )
        projected = project_traveler_trait_targets(conditions, answers)
        by_id = {row.trait_id.value: row.value for row in projected}
        assert by_id[trait_id] == expected


def test_importance_is_only_derived_from_explicit_extremes() -> None:
    from itda.contracts.preference import QuestionnaireAnswersV1

    baseline = _profile()
    non_extreme = QuestionnaireAnswersV1.model_validate(
        {f"q{n}": 3 for n in range(1, 10)} | {"q4": 4, "q7": 4, "q8": 4, "q6": 4, "q9": 4}
    )
    ordinary_conditions = baseline.trip_conditions.model_copy(
        update={
            "visit_time": VisitTime.DAYTIME,
            "walking_tolerance": WalkingTolerance.ABOUT_1_HOUR,
            "crowd_avoidance": CrowdAvoidance.MEDIUM,
        }
    )
    ordinary = project_traveler_trait_targets(ordinary_conditions, non_extreme)
    assert tuple(row.important for row in ordinary) == (False, False, False, False, False, False)

    sunset = ordinary_conditions.model_copy(update={"visit_time": VisitTime.SUNSET})
    evening_high = project_traveler_trait_targets(
        sunset,
        QuestionnaireAnswersV1.model_validate(
            {f"q{n}": 3 for n in range(1, 10)}
            | {"q4": 4, "q7": 4, "q8": 4, "q6": 4, "q9": 4, "q2": 4}
        ),
    )
    assert evening_high[-1].important is True


def test_projection_policy_is_explicitly_versioned() -> None:
    assert RECOMMENDATION_PROJECTION_VERSION == "recommendation-projection-v1"


def _active_recovery_snapshot() -> PublicScoredReleaseSnapshot:
    from itda.contracts.hard_duplicate_adjudication import load_hard_duplicate_adjudication
    from itda.contracts.phase5_recovery_policy import CANONICAL_PHASE5_RECOVERY_POLICY

    policy = CANONICAL_PHASE5_RECOVERY_POLICY
    adjudication = load_hard_duplicate_adjudication()
    profiles = tuple(
        _public_profile(index).model_copy(
            update={
                "place_id": place_id,
                "duplicate_group_id": adjudication.group_id_by_place[place_id],
            }
        )
        for index, place_id in enumerate(policy.cannot_coappear_authority.dev_place_ids, start=1)
    )
    return PublicScoredReleaseSnapshot.model_construct(
        state="ACTIVE",
        schema_version="itda.public-scored-release-snapshot.v5",
        model="minimaxai/minimax-m3",
        prompt_version="phase5-demo-profile-sentinel-json.v5",
        release_sha256="a" * 64,
        membership_sha256=policy.cannot_coappear_authority.dev_membership_sha256,
        hard_duplicate_adjudication_sha256=policy.hard_duplicate_adjudication_sha256,
        hard_duplicate_adjudication=adjudication,
        profiles=profiles,
        snapshot_sha256="b" * 64,
    )


@pytest.mark.parametrize("confidence", (55, 64, 65, 69, 70))
def test_recovery_active_projection_uses_policy_thresholds_without_rank_bonus(
    confidence: int,
) -> None:
    snapshot = _active_recovery_snapshot()
    first = snapshot.profiles[0].model_copy(update={"confidence": confidence})
    qualified = snapshot.model_copy(update={"profiles": (first, *snapshot.profiles[1:])})

    candidate = _recommendation_candidates(qualified)[0]

    assert candidate.overall_confidence == confidence
    assert candidate.recommendation_eligible is True
    assert candidate.publishability.value == (
        "PUBLISHABLE" if confidence >= 70 else "LIMITED_INFORMATION"
    )


def test_recovery_active_projection_rejects_incomplete_release_before_candidates() -> None:
    snapshot = _active_recovery_snapshot()
    incomplete = snapshot.model_copy(update={"profiles": snapshot.profiles[:-1]})

    from itda.application.recommendations import NoActiveScoredRelease

    with pytest.raises(NoActiveScoredRelease):
        _recommendation_candidates(incomplete)
