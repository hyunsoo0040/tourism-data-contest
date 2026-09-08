"""Integer-only, versioned projection of confirmed photo traits.

Blends user-confirmed photo trait values with the existing no-photo
expectation profile using 3,500 photo / 6,500 no-photo basis points and
half-up integer arithmetic. This module never imports or calls recommendation
ranking, tie-break, deduplication, release, or copy builders: it produces a
deterministic expectation profile that is an input to the existing
travel-condition projection only.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Final, Protocol

from itda.contracts.place_profile import MismatchTraitId
from itda.contracts.recommendation import TravelConditionId
from itda.domain.canonical import canonical_sha256
from itda.domain.recommendation_projection import (
    project_traveler_condition_targets,
)

PHOTO_PROJECTION_VERSION: Final[str] = "photo-projection-v1"

NO_PHOTO_BLEND_BP: Final[int] = 6_500
PHOTO_BLEND_BP: Final[int] = 3_500


class _ConfirmedTraitRow(Protocol):
    """Structural row shape the projection reads from confirmed stores."""

    @property
    def trait_id(self) -> str: ...

    @property
    def value(self) -> int: ...

    @property
    def included(self) -> bool: ...


def _half_up(numerator: int, denominator: int) -> int:
    """Round a nonnegative integer ratio half-up using integers only."""

    if type(numerator) is not int or numerator < 0:
        raise ValueError("projection numerator must be a nonnegative integer")
    if type(denominator) is not int or denominator <= 0:
        raise ValueError("projection denominator must be a positive integer")
    return (2 * numerator + denominator) // (2 * denominator)


def _require_images_count(images_count: object) -> int:
    if type(images_count) is not int:
        raise TypeError("images_count must be a strict integer")
    if not 1 <= images_count <= 3:
        raise ValueError("images_count must be 1, 2, or 3")
    return images_count


def _require_value(value: object, *, trait_id: str) -> int:
    if type(value) is not int:
        raise TypeError(f"confirmed trait value for {trait_id} must be a strict integer")
    if not 0 <= value <= 100:
        raise ValueError(f"confirmed trait value for {trait_id} is outside 0-100")
    return value


def _confirmed_rows(confirmed_traits: Sequence[_ConfirmedTraitRow]) -> tuple[
    tuple[str, int], ...
]:
    """Normalize confirmed rows into strict (trait_id, value) pairs."""

    pairs: list[tuple[str, int]] = []
    for row in confirmed_traits:
        if getattr(row, "included", True) is not True:
            continue
        trait_id = row.trait_id
        if not isinstance(trait_id, str) or trait_id not in (
            member.value for member in MismatchTraitId
        ):
            raise ValueError(f"unknown confirmed trait id: {trait_id!r}")
        value = _require_value(row.value, trait_id=trait_id)
        pairs.append((trait_id, value))
    return tuple(pairs)


def _aggregate_equal_shares(
    pairs: Sequence[tuple[str, int]],
    *,
    images_count: int,
) -> dict[str, int]:
    """Aggregate confirmed values with equal per-image integer shares.

    Every confirmed value is first scaled to its per-image rational share
    (value/images_count); same-trait entries sum their scaled shares and the
    canonical ordinal order resolves the reduction. The final half-up
    normalization restores the 0-100 integer scale independent of input order.
    """

    numerator_by_trait: dict[str, int] = {}
    for trait_id, value in pairs:
        numerator_by_trait[trait_id] = numerator_by_trait.get(trait_id, 0) + value
    return {
        trait_id: _half_up(numerator_by_trait[trait_id], images_count)
        for trait_id in sorted(numerator_by_trait)
    }


class PhotoProjectionPolicy:
    """Frozen integer policy identity for photo-projection-v1."""

    no_photo_blend_bp: int
    photo_blend_bp: int
    per_image_share_unit: int

    def __init__(self) -> None:
        object.__setattr__(self, "no_photo_blend_bp", NO_PHOTO_BLEND_BP)
        object.__setattr__(self, "photo_blend_bp", PHOTO_BLEND_BP)
        object.__setattr__(self, "per_image_share_unit", 1)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("PhotoProjectionPolicy is frozen")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("PhotoProjectionPolicy is frozen")

    @property
    def policy_sha256(self) -> str:
        return canonical_sha256(
            {
                "projection_version": PHOTO_PROJECTION_VERSION,
                "no_photo_blend_bp": self.no_photo_blend_bp,
                "photo_blend_bp": self.photo_blend_bp,
                "per_image_share_unit": self.per_image_share_unit,
            }
        )


class PhotoTraitTarget:
    """One projected trait value (integer 0-100) in canonical M1-M6 order."""

    __slots__ = ("trait_id", "value")

    trait_id: MismatchTraitId
    value: int

    def __init__(self, trait_id: MismatchTraitId, value: int) -> None:
        object.__setattr__(self, "trait_id", trait_id)
        object.__setattr__(self, "value", value)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("PhotoTraitTarget is frozen")

    def model_dump(self, *, mode: str = "python") -> dict[str, object]:
        if mode != "json" and mode != "python":
            raise ValueError(f"unsupported dump mode: {mode}")
        return {
            "trait_id": self.trait_id.value if mode == "json" else self.trait_id,
            "value": self.value,
        }


class PhotoConditionTarget:
    """One projected travel-condition value routed through existing authority."""

    __slots__ = ("condition_id", "value")

    condition_id: TravelConditionId
    value: int

    def __init__(self, condition_id: TravelConditionId, value: int) -> None:
        object.__setattr__(self, "condition_id", condition_id)
        object.__setattr__(self, "value", value)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("PhotoConditionTarget is frozen")

    def model_dump(self, *, mode: str = "python") -> dict[str, object]:
        if mode != "json" and mode != "python":
            raise ValueError(f"unsupported dump mode: {mode}")
        return {
            "condition_id": self.condition_id.value if mode == "json" else self.condition_id,
            "value": self.value,
        }


class PhotoProjectionResult:
    """Versioned replay identity plus canonical trait/condition targets."""

    __slots__ = (
        "projection_version",
        "policy_sha256",
        "input_sha256",
        "output_sha256",
        "photo_trait_values",
        "trait_targets",
        "condition_targets",
        "blend_applied",
    )

    projection_version: str
    policy_sha256: str
    input_sha256: str
    output_sha256: str
    photo_trait_values: tuple[tuple[MismatchTraitId, int], ...]
    trait_targets: tuple[PhotoTraitTarget, ...] | None
    condition_targets: tuple[PhotoConditionTarget, ...] | None
    blend_applied: bool

    def __init__(
        self,
        *,
        projection_version: str,
        policy_sha256: str,
        input_sha256: str,
        output_sha256: str,
        photo_trait_values: tuple[tuple[MismatchTraitId, int], ...],
        trait_targets: tuple[PhotoTraitTarget, ...] | None,
        condition_targets: tuple[PhotoConditionTarget, ...] | None,
        blend_applied: bool,
    ) -> None:
        object.__setattr__(self, "projection_version", projection_version)
        object.__setattr__(self, "policy_sha256", policy_sha256)
        object.__setattr__(self, "input_sha256", input_sha256)
        object.__setattr__(self, "output_sha256", output_sha256)
        object.__setattr__(self, "photo_trait_values", photo_trait_values)
        object.__setattr__(self, "trait_targets", trait_targets)
        object.__setattr__(self, "condition_targets", condition_targets)
        object.__setattr__(self, "blend_applied", blend_applied)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("PhotoProjectionResult is frozen")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("PhotoProjectionResult is frozen")

    def model_dump(self, *, mode: str = "python") -> dict[str, object]:
        if mode != "json" and mode != "python":
            raise ValueError(f"unsupported dump mode: {mode}")
        return {
            "projection_version": self.projection_version,
            "policy_sha256": self.policy_sha256,
            "input_sha256": self.input_sha256,
            "output_sha256": self.output_sha256,
            "photo_trait_values": [
                [trait.value if mode == "json" else trait, value]
                for trait, value in self.photo_trait_values
            ],
            "trait_targets": (
                [row.model_dump(mode=mode) for row in self.trait_targets]
                if self.trait_targets is not None
                else None
            ),
            "condition_targets": (
                [row.model_dump(mode=mode) for row in self.condition_targets]
                if self.condition_targets is not None
                else None
            ),
            "blend_applied": self.blend_applied,
        }


def _canonical_input_sha256(
    pairs: Sequence[tuple[str, int]],
    *,
    images_count: int,
    no_photo_trait_values: Mapping[str, int] | None,
    trip_conditions: Mapping[str, object] | None,
    answers: Mapping[str, int] | None,
) -> str:
    return canonical_sha256(
        {
            "projection_version": PHOTO_PROJECTION_VERSION,
            "confirmed_traits": sorted(pairs),
            "images_count": images_count,
            "no_photo_trait_values": dict(sorted(no_photo_trait_values.items()))
            if no_photo_trait_values is not None
            else None,
            "trip_conditions": dict(sorted(trip_conditions.items()))
            if trip_conditions is not None
            else None,
            "answers": dict(sorted(answers.items())) if answers is not None else None,
        }
    )


def combine_confirmed_photo_traits(
    *,
    confirmed_traits: Sequence[_ConfirmedTraitRow],
    images_count: int,
) -> PhotoProjectionResult:
    """Aggregate confirmed included trait values across 1-3 images."""

    policy = PhotoProjectionPolicy()
    count = _require_images_count(images_count)
    pairs = _confirmed_rows(confirmed_traits)
    aggregated = _aggregate_equal_shares(pairs, images_count=count)
    photo_trait_values = tuple(
        (MismatchTraitId(trait_id), value)
        for trait_id, value in sorted(aggregated.items())
    )
    input_sha256 = _canonical_input_sha256(
        pairs, images_count=count, no_photo_trait_values=None, trip_conditions=None,
        answers=None,
    )
    output_sha256 = canonical_sha256(
        {
            "projection_version": PHOTO_PROJECTION_VERSION,
            "input_sha256": input_sha256,
            "photo_trait_values": [
                [trait.value, value] for trait, value in photo_trait_values
            ],
        }
    )
    return PhotoProjectionResult(
        projection_version=PHOTO_PROJECTION_VERSION,
        policy_sha256=policy.policy_sha256,
        input_sha256=input_sha256,
        output_sha256=output_sha256,
        photo_trait_values=photo_trait_values,
        trait_targets=None,
        condition_targets=None,
        blend_applied=bool(photo_trait_values),
    )


def _require_no_photo_values(
    no_photo_trait_values: Mapping[str, int],
) -> dict[MismatchTraitId, int]:
    required = tuple(member.value for member in MismatchTraitId)
    if tuple(sorted(no_photo_trait_values)) != tuple(sorted(required)):
        raise ValueError("no_photo_trait_values must contain exactly M1-M6")
    resolved: dict[MismatchTraitId, int] = {}
    for member in MismatchTraitId:
        value = no_photo_trait_values[member.value]
        if type(value) is not int or not 0 <= value <= 100:
            raise ValueError(f"no-photo value for {member.value} must be integer 0-100")
        resolved[member] = value
    return resolved


def project_photo_confirmed_profile(
    *,
    confirmed_traits: Sequence[_ConfirmedTraitRow],
    images_count: int,
    no_photo_trait_values: Mapping[str, int],
    trip_conditions: Mapping[str, object] | None = None,
    answers: Mapping[str, int] | None = None,
    questionnaire_version: str | None = None,
) -> PhotoProjectionResult:
    """Blend confirmed photo traits into the no-photo expectation profile.

    Uses 3,500 photo / 6,500 no-photo basis points with half-up integer
    arithmetic. Travel conditions are routed through the existing server-owned
    projection authority; ranking, tie-break, deduplication, and copy builders
    are never referenced. Answer validation is questionnaire-version-aware:
    whenever ``trip_conditions`` is supplied, ``questionnaire_version`` is
    required explicitly (there is no silent default to v1) and must name the
    generation the answers were captured under.
    """

    policy = PhotoProjectionPolicy()
    count = _require_images_count(images_count)
    pairs = _confirmed_rows(confirmed_traits)
    aggregated = _aggregate_equal_shares(pairs, images_count=count)
    photo_trait_values = tuple(
        (MismatchTraitId(trait_id), value)
        for trait_id, value in sorted(aggregated.items())
    )

    no_photo = _require_no_photo_values(no_photo_trait_values)
    total_bp = NO_PHOTO_BLEND_BP + PHOTO_BLEND_BP
    blended: dict[MismatchTraitId, int] = {}
    for member in MismatchTraitId:
        if not photo_trait_values:
            # Zero confirmed traits reproduce the original no-photo profile.
            blended[member] = no_photo[member]
            continue
        photo_value = dict(photo_trait_values).get(member, 0)
        blended[member] = _half_up(
            PHOTO_BLEND_BP * photo_value + NO_PHOTO_BLEND_BP * no_photo[member],
            total_bp,
        )
    trait_targets = tuple(
        PhotoTraitTarget(member, blended[member]) for member in MismatchTraitId
    )

    condition_targets: tuple[PhotoConditionTarget, ...] | None = None
    if trip_conditions is not None:
        if answers is None:
            raise ValueError("trip_conditions require the questionnaire answers")
        if questionnaire_version is None:
            raise ValueError(
                "trip_conditions require an explicit questionnaire_version; "
                "photo answer validation must never default to a generation"
            )
        condition_targets = _project_condition_targets(
            trip_conditions=trip_conditions,
            answers=answers,
            questionnaire_version=questionnaire_version,
        )

    input_sha256 = _canonical_input_sha256(
        pairs,
        images_count=count,
        no_photo_trait_values=no_photo_trait_values,
        trip_conditions=trip_conditions,
        answers=answers,
    )
    output_sha256 = canonical_sha256(
        {
            "projection_version": PHOTO_PROJECTION_VERSION,
            "input_sha256": input_sha256,
            "photo_trait_values": [
                [trait.value, value] for trait, value in photo_trait_values
            ],
            "trait_targets": [row.model_dump(mode="json") for row in trait_targets],
            "condition_targets": (
                [row.model_dump(mode="json") for row in condition_targets]
                if condition_targets is not None
                else None
            ),
        }
    )
    return PhotoProjectionResult(
        projection_version=PHOTO_PROJECTION_VERSION,
        policy_sha256=policy.policy_sha256,
        input_sha256=input_sha256,
        output_sha256=output_sha256,
        photo_trait_values=photo_trait_values,
        trait_targets=trait_targets,
        condition_targets=condition_targets,
        blend_applied=bool(photo_trait_values),
    )


def _project_condition_targets(
    *,
    trip_conditions: Mapping[str, object],
    answers: Mapping[str, int],
    questionnaire_version: str,
) -> tuple[PhotoConditionTarget, ...]:
    """Route travel-condition projection through the existing authority.

    ``questionnaire_version`` is required and must be a known generation; an
    unknown value fails closed instead of falling back to v1 validation.
    """

    from itda.contracts.preference import (
        CompanionType,
        CrowdAvoidance,
        IndoorOutdoorPreference,
        QuestionnaireAnswersV1,
        QuestionnaireAnswersV2,
        TransportType,
        TripConditions,
        VisitTime,
        WalkingTolerance,
    )

    required_condition_keys = (
        "visit_time",
        "companion",
        "transport",
        "walking_tolerance",
        "indoor_outdoor_preference",
        "crowd_avoidance",
    )
    for key in required_condition_keys:
        if key not in trip_conditions:
            raise ValueError(f"trip_conditions is missing {key}")
    conditions = TripConditions.model_validate(
        {
            "visit_date": trip_conditions.get("visit_date"),
            "visit_time": VisitTime(trip_conditions["visit_time"]),  # type: ignore[arg-type]
            "companion": CompanionType(trip_conditions["companion"]),  # type: ignore[arg-type]
            "transport": TransportType(trip_conditions["transport"]),  # type: ignore[arg-type]
            "walking_tolerance": WalkingTolerance(trip_conditions["walking_tolerance"]),  # type: ignore[arg-type]
            "indoor_outdoor_preference": IndoorOutdoorPreference(
                trip_conditions["indoor_outdoor_preference"]  # type: ignore[arg-type]
            ),
            "crowd_avoidance": CrowdAvoidance(trip_conditions["crowd_avoidance"]),  # type: ignore[arg-type]
        }
    )
    # Validation is intentional even without a returned value: answers must
    # parse as the strict questionnaire contract for the declared version
    # before any projection runs. Unknown versions fail closed.
    if questionnaire_version == "questionnaire-v2":
        QuestionnaireAnswersV2.model_validate(answers)
    elif questionnaire_version == "questionnaire-v1":
        QuestionnaireAnswersV1.model_validate(answers)
    else:
        raise ValueError(
            f"unsupported questionnaire_version for photo answers: {questionnaire_version}"
        )
    targets = project_traveler_condition_targets(conditions)
    return tuple(PhotoConditionTarget(row.condition_id, row.value) for row in targets)


__all__ = [
    "NO_PHOTO_BLEND_BP",
    "PHOTO_BLEND_BP",
    "PHOTO_PROJECTION_VERSION",
    "PhotoConditionTarget",
    "PhotoProjectionPolicy",
    "PhotoProjectionResult",
    "PhotoTraitTarget",
    "combine_confirmed_photo_traits",
    "project_photo_confirmed_profile",
]
