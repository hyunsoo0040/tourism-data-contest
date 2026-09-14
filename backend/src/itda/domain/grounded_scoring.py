"""Fixed arithmetic on supported dimensions; no provider or raw-profile access."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from itda.contracts.grounded_recommendation import GroundedFitComponent, GroundedFitTrace
from itda.contracts.source_assessment import SourceObservation, SupportState


def half_up(numerator: int, denominator: int) -> int:
    if (
        type(numerator) is not int
        or type(denominator) is not int
        or numerator < 0
        or denominator <= 0
    ):
        raise ValueError("invalid nonnegative rational score")
    return (2 * numerator + denominator) // (2 * denominator)


def observed_value(row: SourceObservation | None) -> int | None:
    if row is None or row.state == SupportState.UNKNOWN:
        return None
    if type(row.value) is not int or not 0 <= row.value <= 100:
        raise ValueError("score channel requires an observed 0–100 integer")
    return row.value


def fit_trace(
    expected: Mapping[str, int | None],
    actual: Mapping[str, SourceObservation],
    *,
    weights: Mapping[str, int] | None = None,
) -> GroundedFitTrace:
    components = []
    for key, target in sorted(expected.items()):
        row = actual.get(key)
        value = observed_value(row)
        compared = target is not None and value is not None
        difference = abs(target - value) if target is not None and value is not None else None
        components.append(
            GroundedFitComponent(
                key=key,
                expected=target,
                actual=value,
                compared=compared,
                difference=difference,
                fit=100 - difference if difference is not None else None,
                weight=(weights[key] if weights is not None else 1) if compared else 0,
                evidence_ids=tuple(sorted({e.evidence_id for e in row.evidence}))
                if row is not None and value is not None
                else (),
                exclusion_reason=None
                if compared
                else "USER_UNSPECIFIED"
                if target is None
                else "PLACE_UNSUPPORTED",
            )
        )
    numerator = sum(row.fit * row.weight for row in components if row.fit is not None)
    denominator = sum(row.weight for row in components)
    return GroundedFitTrace(
        components=tuple(components),
        numerator=numerator,
        denominator=denominator,
        score=half_up(numerator, denominator) if denominator else None,
        compared_keys=tuple(c.key for c in components if c.compared),
    )


def combine_groups(groups: tuple[tuple[int | None, int], ...]) -> int | None:
    supported = [(value, weight) for value, weight in groups if value is not None and weight > 0]
    if not supported:
        return None
    return half_up(
        sum(value * weight for value, weight in supported), sum(weight for _, weight in supported)
    )


@dataclass(frozen=True)
class GroundedMismatch:
    axis_distance: int | None
    trait_distance: int | None
    raw_score: int | None
    effective_score: int | None
    compared_traits: tuple[str, ...]
    important_floor_applied: bool
    state: str


def mismatch(
    axis_fit: GroundedFitTrace,
    trait_fit: GroundedFitTrace,
    *,
    important_traits: frozenset[str],
    confidence: int,
) -> GroundedMismatch:
    axis_distance = 100 - axis_fit.score if axis_fit.score is not None else None
    trait_distance = 100 - trait_fit.score if trait_fit.score is not None else None
    raw = combine_groups(((axis_distance, 6500), (trait_distance, 3500)))
    floor = any(
        c.key in important_traits and c.compared and c.difference is not None and c.difference >= 70
        for c in trait_fit.components
    )
    effective = max(raw, 50) if raw is not None and floor else raw
    state = (
        "INSUFFICIENT_EVIDENCE"
        if effective is None
        else "SUPPRESSED_LOW_CONFIDENCE"
        if confidence < 65
        else "NO_GUIDANCE"
        if effective < 30
        else "GENTLE_DIFFERENCE"
        if effective < 45
        else "MATERIAL_DIFFERENCE"
        if effective < 60
        else "STRONG_DIFFERENCE"
    )
    return GroundedMismatch(
        axis_distance, trait_distance, raw, effective, trait_fit.compared_keys, floor, state
    )


def pair_novelty(
    left: Mapping[str, SourceObservation], right: Mapping[str, SourceObservation]
) -> int:
    return pair_distance(
        {k: observed_value(v) for k, v in left.items()},
        {k: observed_value(v) for k, v in right.items()},
    )


def pair_distance(left: Mapping[str, int | None], right: Mapping[str, int | None]) -> int:
    distances = []
    for keys, weight in [(tuple("HER"), 6500), (tuple(f"M{i}" for i in range(1, 7)), 3500)]:
        pairs = [(left.get(key), right.get(key)) for key in keys]
        values = [abs(a - b) for a, b in pairs if a is not None and b is not None]
        distances.append((half_up(sum(values), len(values)) if values else None, weight))
    value = combine_groups(tuple(distances))
    return value if value is not None else 0


def novelty(
    candidate: Mapping[str, SourceObservation],
    selected: tuple[Mapping[str, SourceObservation], ...],
) -> int:
    return min(pair_novelty(candidate, prior) for prior in selected) if selected else 0
