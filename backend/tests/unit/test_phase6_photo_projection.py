"""Wave 0 controlled-RED contracts for the Phase 6 integer photo projection.

Freezes ``photo-projection-v1``: integer-only half-up arithmetic, canonical
policy digest, 1/2/3-image equal-share aggregation, permutation independence,
duplicate handling, 6,500/3,500 basis-point blend with the no-photo profile,
travel-condition projection through the existing server-owned input,
byte-identical replay, boundary values, and rejection of bool/float/unknown
versions. The module fails only on the absent
``itda.domain.photo_projection`` implementation.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from itda.contracts.place_profile import MismatchTraitId
from itda.domain.canonical import canonical_json_bytes


def _projection():
    import itda.domain.photo_projection as photo_projection

    return photo_projection


def _mismatch_enum():
    # Imported lazily: importing itda.contracts.recommendation transitively
    # validates the phase5 recovery policy, whose historical 05-16 plan path
    # moved under .planning/milestones after the v1.0 archive. That pre-existing
    # drift must not mask this module's controlled-RED owner absence.
    from itda.contracts.recommendation import TravelConditionId

    return TravelConditionId


class _ConfirmedTrait:
    """Minimal confirmed-value stand-in matching the store row shape."""

    def __init__(self, trait_id: str, value: int) -> None:
        self.trait_id = trait_id
        self.value = value
        self.text_ko = f"선호 {trait_id}"
        self.provenance = "USER_CONFIRMED"
        self.included = True


def _traits(*pairs: tuple[str, int]) -> tuple[_ConfirmedTrait, ...]:
    return tuple(_ConfirmedTrait(trait_id, value) for trait_id, value in pairs)


def test_projection_version_and_policy_are_frozen() -> None:
    projection = _projection()
    assert projection.PHOTO_PROJECTION_VERSION == "photo-projection-v1"

    policy = projection.PhotoProjectionPolicy()
    assert policy.no_photo_blend_bp == 6_500
    assert policy.photo_blend_bp == 3_500
    assert policy.no_photo_blend_bp + policy.photo_blend_bp == 10_000
    numeric_authority = {
        name: value
        for name, value in vars(policy).items()
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    }
    assert numeric_authority, "policy must expose integer weight authority"
    assert all(
        type(value) is int for value in numeric_authority.values()
    ), "policy numeric authority must be integers only"
    assert all(
        "float" not in repr(value) for value in vars(policy).values()
    )


def test_policy_and_results_bind_canonical_digests() -> None:
    projection = _projection()

    policy = projection.PhotoProjectionPolicy()
    assert policy.policy_sha256
    assert len(policy.policy_sha256) == 64

    result = projection.combine_confirmed_photo_traits(
        confirmed_traits=_traits(("M5", 80)),
        images_count=1,
    )
    assert result.projection_version == "photo-projection-v1"
    assert result.policy_sha256 == policy.policy_sha256
    assert result.input_sha256
    assert result.output_sha256
    assert len(result.input_sha256) == 64
    assert len(result.output_sha256) == 64


def test_one_two_three_image_equal_share_aggregation() -> None:
    projection = _projection()

    single = projection.combine_confirmed_photo_traits(
        confirmed_traits=_traits(("M5", 80)),
        images_count=1,
    )
    assert single.photo_trait_values == ((MismatchTraitId.M5, 80),)

    two_images = projection.combine_confirmed_photo_traits(
        confirmed_traits=_traits(("M5", 60), ("M5", 70)),
        images_count=2,
    )
    assert two_images.photo_trait_values == ((MismatchTraitId.M5, 65),)

    three_images = projection.combine_confirmed_photo_traits(
        confirmed_traits=_traits(("M5", 60), ("M5", 70), ("M5", 80)),
        images_count=3,
    )
    assert three_images.photo_trait_values == ((MismatchTraitId.M5, 70),)


def test_half_up_boundaries_are_exact() -> None:
    projection = _projection()

    two_half = projection.combine_confirmed_photo_traits(
        confirmed_traits=_traits(("M5", 61), ("M5", 62)),
        images_count=2,
    )
    assert two_half.photo_trait_values == ((MismatchTraitId.M5, 62),)

    three_thirds = projection.combine_confirmed_photo_traits(
        confirmed_traits=_traits(("M5", 61), ("M5", 61), ("M5", 62)),
        images_count=3,
    )
    assert three_thirds.photo_trait_values == ((MismatchTraitId.M5, 61),)

    exact_split = projection.combine_confirmed_photo_traits(
        confirmed_traits=_traits(("M5", 50), ("M5", 50)),
        images_count=2,
    )
    assert exact_split.photo_trait_values == ((MismatchTraitId.M5, 50),)


@pytest.mark.parametrize("images_count", (1, 2, 3))
def test_permutation_independence(images_count: int) -> None:
    projection = _projection()
    values: list[tuple[str, int]] = [("M5", 60), ("M5", 75), ("M2", 40)][: max(images_count, 2)]

    forward = projection.combine_confirmed_photo_traits(
        confirmed_traits=_traits(*values), images_count=images_count
    )
    reversed_input = projection.combine_confirmed_photo_traits(
        confirmed_traits=_traits(*reversed(values)), images_count=images_count
    )
    assert (
        canonical_json_bytes(forward.model_dump(mode="json"))
        == canonical_json_bytes(reversed_input.model_dump(mode="json"))
    ), "input order must not affect the projection result"


def test_duplicate_traits_deduplicate_deterministically() -> None:
    projection = _projection()

    duplicated = projection.combine_confirmed_photo_traits(
        confirmed_traits=_traits(("M5", 70), ("M5", 70), ("M5", 70)),
        images_count=3,
    )
    assert duplicated.photo_trait_values == ((MismatchTraitId.M5, 70),)

    mixed = projection.combine_confirmed_photo_traits(
        confirmed_traits=_traits(("M2", 30), ("M5", 70)),
        images_count=1,
    )
    assert tuple(trait for trait, _value in mixed.photo_trait_values) == (
        MismatchTraitId.M2,
        MismatchTraitId.M5,
    ), "output order must be canonical M1-M6, not input order"


def test_blend_with_no_photo_profile_uses_frozen_basis_points() -> None:
    projection = _projection()

    no_photo_values = {"M1": 13, "M2": 25, "M3": 50, "M4": 75, "M5": 88, "M6": 63}
    result = projection.project_photo_confirmed_profile(
        confirmed_traits=_traits(("M5", 100), ("M2", 0)),
        images_count=1,
        no_photo_trait_values=no_photo_values,
    )
    # 6,500/3,500 blend, half-up: round(0.35 * photo + 0.65 * no_photo).
    expected_m5 = (3_500 * 100 + 6_500 * 88 + 5_000) // 10_000
    expected_m2 = (3_500 * 0 + 6_500 * 25 + 5_000) // 10_000
    assert result.trait_targets is not None
    by_trait = {row.trait_id: row.value for row in result.trait_targets}
    assert by_trait[MismatchTraitId.M5] == expected_m5
    assert by_trait[MismatchTraitId.M2] == expected_m2


def test_travel_conditions_route_through_existing_projection_input() -> None:
    from itda.contracts.preference import (
        CompanionType,
        CrowdAvoidance,
        IndoorOutdoorPreference,
        TransportType,
        VisitTime,
        WalkingTolerance,
    )

    TravelConditionId = _mismatch_enum()
    projection = _projection()

    result = projection.project_photo_confirmed_profile(
        confirmed_traits=_traits(("M5", 80)),
        images_count=1,
        no_photo_trait_values={"M1": 13, "M2": 25, "M3": 50, "M4": 75, "M5": 88, "M6": 63},
        trip_conditions={
            "visit_date": None,
            "visit_time": VisitTime.EVENING,
            "companion": CompanionType.FAMILY_WITH_CHILDREN,
            "transport": TransportType.CAR_OR_TAXI,
            "walking_tolerance": WalkingTolerance.EXTENDED_WALKING_OK,
            "indoor_outdoor_preference": IndoorOutdoorPreference.OUTDOOR,
            "crowd_avoidance": CrowdAvoidance.HIGH,
        },
        answers={"q1": 3, "q2": 4, "q3": 3, "q4": 5, "q5": 3, "q6": 5, "q7": 5, "q8": 2, "q9": 1},
        questionnaire_version="questionnaire-v1",
    )
    assert result.condition_targets is not None
    assert tuple(row.condition_id for row in result.condition_targets) == tuple(
        TravelConditionId
    )
    by_condition = {row.condition_id: row.value for row in result.condition_targets}
    assert by_condition[TravelConditionId.VISIT_DATE_TIME] == 100
    assert by_condition[TravelConditionId.COMPANIONS] == 75
    assert by_condition[TravelConditionId.CROWD] == 100


def test_byte_identical_replay() -> None:
    projection = _projection()

    inputs = {
        "confirmed_traits": _traits(("M5", 80), ("M2", 30)),
        "images_count": 2,
        "no_photo_trait_values": {"M1": 13, "M2": 25, "M3": 50, "M4": 75, "M5": 88, "M6": 63},
    }
    first = projection.project_photo_confirmed_profile(**inputs)
    second = projection.project_photo_confirmed_profile(**inputs)
    assert canonical_json_bytes(first.model_dump(mode="json")) == canonical_json_bytes(
        second.model_dump(mode="json")
    )
    assert first.output_sha256 == second.output_sha256


def test_zero_confirmed_traits_preserve_no_photo_profile() -> None:
    projection = _projection()

    no_photo_values = {"M1": 13, "M2": 25, "M3": 50, "M4": 75, "M5": 88, "M6": 63}
    result = projection.project_photo_confirmed_profile(
        confirmed_traits=(),
        images_count=1,
        no_photo_trait_values=no_photo_values,
    )
    by_trait = {row.trait_id: row.value for row in result.trait_targets}
    assert by_trait == {
        MismatchTraitId.M1: 13,
        MismatchTraitId.M2: 25,
        MismatchTraitId.M3: 50,
        MismatchTraitId.M4: 75,
        MismatchTraitId.M5: 88,
        MismatchTraitId.M6: 63,
    }


def test_images_count_bounds_and_type_rejection() -> None:
    projection = _projection()

    for bad_count in (0, 4, -1, 1.0, True, "2"):
        with pytest.raises((TypeError, ValueError)):
            projection.combine_confirmed_photo_traits(
                confirmed_traits=_traits(("M5", 80)),
                images_count=bad_count,  # type: ignore[arg-type]
            )


def test_confirmed_trait_type_authority_is_strict() -> None:
    projection = _projection()

    for bad_value in (80.0, True, "80", None):
        with pytest.raises((TypeError, ValueError)):
            projection.combine_confirmed_photo_traits(
                confirmed_traits=(_ConfirmedTrait("M5", 0), _RejectingTrait(bad_value)),  # type: ignore[list-item]
                images_count=1,
            )


class _RejectingTrait:
    """A confirmed row whose value violates the integer-only authority."""

    def __init__(self, value: object) -> None:
        self.trait_id = "M5"
        self.value = value
        self.text_ko = "선호 M5"
        self.provenance = "USER_CONFIRMED"
        self.included = True


def test_projection_module_never_imports_recommendation_authority() -> None:
    source_path = inspect.getsourcefile(_projection())
    assert source_path is not None
    source = Path(source_path).read_text(encoding="utf-8")

    forbidden_imports = (
        "itda.domain.recommendation import",
        "itda.domain.mvp_recommendation",
        "rank_recommendations",
        "rank_mvp_top_five",
        "create_mvp_recommendation_run",
        "_suppress_duplicates",
        "_maximum_compatible_ids",
    )
    for fragment in forbidden_imports:
        assert fragment not in source, f"projection must not reference {fragment}"

    projection = _projection()
    for symbol in (
        "rank_recommendations",
        "rank_mvp_top_five",
        "create_mvp_recommendation_run",
    ):
        assert not hasattr(projection, symbol), symbol


def test_missing_questionnaire_version_fails_closed_not_silently_v1() -> None:
    """A v2-shaped answers payload without an explicit version must be rejected.

    If questionnaire_version silently defaulted to v1, v2 answers (q1..q12,
    values 1..3) would be parsed as v1 and either rejected as corrupt or
    misread; the projection requires the declared generation instead.
    """

    projection = _projection()

    with pytest.raises(ValueError, match="explicit questionnaire_version"):
        projection.project_photo_confirmed_profile(
            confirmed_traits=_traits(("M5", 80)),
            images_count=1,
            no_photo_trait_values={"M1": 13, "M2": 25, "M3": 50, "M4": 75, "M5": 88, "M6": 63},
            trip_conditions={
                "visit_date": None,
                "visit_time": "UNDECIDED",
                "companion": "SOLO",
                "transport": "WALK_OR_TRANSIT",
                "walking_tolerance": "ABOUT_1_HOUR",
                "indoor_outdoor_preference": "NO_PREFERENCE",
                "crowd_avoidance": "MEDIUM",
            },
            answers={f"q{number}": 2 for number in range(1, 13)},
        )


def test_v2_answers_validate_only_under_their_declared_version() -> None:
    """v2 q10..q12 answers validate under v2 but not under v1 validation."""

    projection = _projection()
    conditions = {
        "visit_date": None,
        "visit_time": "UNDECIDED",
        "companion": "SOLO",
        "transport": "WALK_OR_TRANSIT",
        "walking_tolerance": "ABOUT_1_HOUR",
        "indoor_outdoor_preference": "NO_PREFERENCE",
        "crowd_avoidance": "MEDIUM",
    }
    v2_answers = {f"q{number}": 2 for number in range(1, 13)}

    accepted = projection.project_photo_confirmed_profile(
        confirmed_traits=_traits(("M5", 80)),
        images_count=1,
        no_photo_trait_values={"M1": 13, "M2": 25, "M3": 50, "M4": 75, "M5": 88, "M6": 63},
        trip_conditions=conditions,
        answers=v2_answers,
        questionnaire_version="questionnaire-v2",
    )
    assert accepted.condition_targets is not None

    # The same payload declared as v1 fails closed: without the version-coupled
    # check q10..q12 would silently become missing v1 arguments.
    with pytest.raises(ValueError):
        projection.project_photo_confirmed_profile(
            confirmed_traits=_traits(("M5", 80)),
            images_count=1,
            no_photo_trait_values={"M1": 13, "M2": 25, "M3": 50, "M4": 75, "M5": 88, "M6": 63},
            trip_conditions=conditions,
            answers=v2_answers,
            questionnaire_version="questionnaire-v1",
        )

    # Unknown generations fail closed rather than falling back to v1.
    with pytest.raises(ValueError, match="unsupported questionnaire_version"):
        projection.project_photo_confirmed_profile(
            confirmed_traits=_traits(("M5", 80)),
            images_count=1,
            no_photo_trait_values={"M1": 13, "M2": 25, "M3": 50, "M4": 75, "M5": 88, "M6": 63},
            trip_conditions=conditions,
            answers=v2_answers,
            questionnaire_version="questionnaire-v9",
        )
