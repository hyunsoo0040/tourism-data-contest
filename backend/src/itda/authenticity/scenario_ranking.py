"""Versioned, axis-only bridge from retained scenarios to current place assessments.

Scenario relative weights are not direct facet importance/intensity/avoidance.
Confirmed photo preferences use 20% of the available comparison weight; without
photos the three axis weights account for 100%. Missing evidence is never zero.
"""

from collections.abc import Mapping
from typing import Any

from itda.authenticity.contracts import Assessment
from itda.authenticity.intent import Intent, ScenarioSubmission, scenario_weights
from itda.authenticity.scoring import verify_assessment
from itda.authenticity.visual import VISUAL_FACETS, compare_visual
from itda.contracts.destination_mood import DestinationMoodBundle
from itda.contracts.grounded_recommendation import RequiredFacility
from itda.contracts.source_assessment import ClaimKind, SourceObservation, SupportState
from itda.domain.grounded_scoring import half_up


def scenario_candidates(
    assessments: tuple[Assessment, ...],
    intent: Intent,
    facility_facts: Mapping[str, Mapping[RequiredFacility, SourceObservation]] | None,
    visual_references: Mapping[str, DestinationMoodBundle] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    sub = intent.submission
    assert isinstance(sub, ScenarioSubmission)
    photo_facets = sorted({VISUAL_FACETS[d] for d in sub.visual_targets})
    weights = scenario_weights(sub, 8000 if photo_facets else 10_000)
    scored: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    for assessment in sorted(assessments, key=lambda a: a.source.place.place_id):
        verify_assessment(assessment)
        place = assessment.source.place
        axes = {axis.axis: axis for axis in assessment.axes}
        facets = {facet.key: facet for facet in assessment.facets}
        reason = None
        if not any(weights.values()):
            reason = "NO_EXPERIENCE_EXPECTATIONS"
        elif sub.requirements.region_code and not place.region_code.startswith(
            sub.requirements.region_code
        ):
            reason = "REGION"
        elif any(axes[axis].value is None for axis in intent.required_axes):
            reason = "IMPORTANT_AXIS_UNSUPPORTED"
        for requirement in sub.requirements.required_facilities:
            fact = (facility_facts or {}).get(place.place_id, {}).get(requirement)
            if (
                fact is None
                or fact.state != SupportState.FACT
                or fact.claim != ClaimKind.FACILITY
                or type(fact.value) is not bool
            ):
                reason = reason or "REQUIRED_FACILITY_UNCONFIRMED"
            else:
                SourceObservation.model_validate_json(fact.model_dump_json())
                if any(
                    e.place_match is None or e.place_match.place_id != place.place_id
                    for e in fact.evidence
                ):
                    raise ValueError("FACILITY_FACT_PLACE_MISMATCH")
                if not fact.value:
                    reason = reason or "REQUIRED_FACILITY_ABSENT"
        components: list[dict[str, Any]] = []
        for axis, weight in weights.items():
            if weight == 0:
                continue
            value = axes[axis].value
            evidence = sorted(
                {
                    eid
                    for f in assessment.facets
                    if f.key.startswith(axis + ".")
                    for c in f.contributions
                    for eid in c.evidence_ids
                }
            )
            components.append(
                {
                    "facet": axis,
                    "importance": None,
                    "avoidance": 0,
                    "desired_level": None,
                    "place_value": value,
                    "utility": value,
                    "weight": weight,
                    "compared": value is not None,
                    "visual_comparison": [],
                    "evidence_ids": evidence if value is not None else [],
                    "rule": "SCENARIO_RELATIVE_AXIS_WEIGHT",
                }
            )
        for index, key in enumerate(photo_facets):
            weight = 2000 // len(photo_facets) + int(index < 2000 % len(photo_facets))
            facet = facets[key]
            value = facet.value
            utility, visual = compare_visual(
                key, sub.visual_targets, (visual_references or {}).get(place.place_id)
            )
            if (
                next(a.value for a in assessment.axes if key.startswith(a.axis + ".")) is None
                or value is None
            ):
                utility = None
            components.append(
                {
                    "facet": key,
                    "importance": None,
                    "avoidance": 0,
                    "desired_level": None,
                    "place_value": value,
                    "utility": utility,
                    "weight": weight,
                    "compared": utility is not None,
                    "visual_comparison": visual,
                    "evidence_ids": sorted(
                        {eid for c in facet.contributions for eid in c.evidence_ids}
                    )
                    if utility is not None
                    else [],
                    "rule": "CONFIRMED_VISUAL_FACET_MATCH",
                }
            )
        total = sum(c["weight"] for c in components)
        known = sum(c["weight"] for c in components if c["compared"])
        if not reason and (known == 0 or known * 2 < total):
            reason = "INSUFFICIENT_EXPECTATION_COVERAGE"
        if reason:
            excluded.append({"place_id": place.place_id, "reason": reason})
            continue
        scored.append(
            {
                "place_id": place.place_id,
                "name_ko": place.name_ko,
                "region_name": place.region_name,
                "category": place.category,
                "assessment_sha256": assessment.assessment_sha256,
                "duplicate_group_id": place.duplicate_group_id,
                "score": half_up(
                    sum(c["utility"] * c["weight"] for c in components if c["compared"]), known
                ),
                "coverage": {
                    "known_weight": known,
                    "total_weight": total,
                    "percent": half_up(100 * known, total),
                },
                "axes": {axis: score.value for axis, score in axes.items()},
                "components": components,
                "warnings": ["MISSING_EXPECTATION_EVIDENCE"] if known < total else [],
            }
        )
    return scored, excluded
