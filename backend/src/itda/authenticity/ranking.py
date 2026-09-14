"""Personalized fulfillment with explicit intensity/avoidance and no popularity bonus."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any, cast

from itda.authenticity.contracts import Assessment
from itda.authenticity.intent import Intent, effective_importance
from itda.authenticity.rubric import FACET_KEYS, Axis
from itda.authenticity.scoring import verify_assessment
from itda.authenticity.visual import VISUAL_FACETS, compare_visual
from itda.contracts.base import require_utc
from itda.contracts.destination_mood import DestinationMoodBundle
from itda.contracts.grounded_recommendation import RequiredFacility
from itda.contracts.source_assessment import ClaimKind, SourceObservation, SupportState
from itda.domain.canonical import canonical_sha256
from itda.domain.grounded_scoring import half_up

RANKING_VERSION = "authenticity-fulfillment-v1"


def rank(
    *,
    assessments: tuple[Assessment, ...],
    intent: Intent,
    created_at: datetime,
    facility_facts: Mapping[str, Mapping[RequiredFacility, SourceObservation]] | None = None,
    forbidden_pairs: tuple[tuple[str, str], ...] = (),
    limit: int = 5,
    request_id: str | None = None,
    visual_references: Mapping[str, DestinationMoodBundle] | None = None,
) -> dict[str, Any]:
    if type(limit) is not int or not 1 <= limit <= 5:
        raise ValueError("RECOMMENDATION_LIMIT_MUST_BE_1_TO_5")
    require_utc(created_at, field_name="created_at")
    Intent.model_validate_json(intent.model_dump_json())
    ids = [a.source.place.place_id for a in assessments]
    if len(set(ids)) != len(ids):
        raise ValueError("DUPLICATED_CANDIDATE")
    policy_hashes = {a.policy.policy_sha256 for a in assessments}
    if len(policy_hashes) > 1:
        raise ValueError("CANNOT_RANK_MIXED_SCORING_POLICIES")
    forbidden = {frozenset(p) for p in forbidden_pairs}
    if any(len(p) != 2 or not p <= set(ids) for p in forbidden):
        raise ValueError("FORBIDDEN_RELATION_MEMBERSHIP_MISMATCH")
    sub = intent.submission
    weights = effective_importance(sub)
    total_weight = sum(v or 0 for v in weights.values()) + sum(sub.avoid.values())
    excluded: list[dict[str, Any]] = []
    scored: list[dict[str, Any]] = []
    for assessment in sorted(assessments, key=lambda a: a.source.place.place_id):
        verify_assessment(assessment)
        place = assessment.source.place
        axes = {a.axis: a for a in assessment.axes}
        facets = {f.key: f for f in assessment.facets}
        reason = None
        if total_weight == 0:
            reason = "NO_EXPERIENCE_EXPECTATIONS"
        elif sub.requirements.region_code and not place.region_code.startswith(
            sub.requirements.region_code
        ):
            reason = "REGION"
        elif any(axes[a].value is None for a in intent.required_axes):
            reason = "IMPORTANT_AXIS_UNSUPPORTED"
        elif any((weights[k] or 0) >= 3 and facets[k].value is None for k in FACET_KEYS):
            reason = "IMPORTANT_FACET_UNSUPPORTED"
        elif any(v >= 3 and facets[k].value is None for k, v in sub.avoid.items()):
            reason = "AVOIDANCE_UNCONFIRMED"
        elif intent.requested_axes and not any(
            axes[a].value is not None for a in intent.requested_axes
        ):
            reason = "REQUESTED_AXES_UNSUPPORTED"
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
        known_weight = 0
        for key in FACET_KEYS:
            weight = weights[key] or 0
            avoid = sub.avoid.get(key, 0)
            if not weight and not avoid:
                continue
            facet = facets[key]
            # A partial facet cannot bypass its axis's semantic-core gate.
            value = facet.value if axes[cast(Axis, key[0])].value is not None else None
            desired = sub.desired_levels.get(key)
            utility = None
            visual_parts: list[dict[str, Any]] = []
            owns_visual = any(VISUAL_FACETS[d] == key for d in sub.visual_targets)
            if value is not None:
                utility = (
                    100 - value
                    if avoid
                    else 100 - abs(value - desired * 25)
                    if desired is not None
                    else value
                )
                if owns_visual:
                    utility, visual_parts = compare_visual(
                        key, sub.visual_targets, (visual_references or {}).get(place.place_id)
                    )
                if owns_visual and utility is None and weight >= 3:
                    reason = reason or "IMPORTANT_VISUAL_UNSUPPORTED"
                if utility is not None:
                    known_weight += avoid or weight
            components.append(
                {
                    "facet": key,
                    "importance": weight,
                    "avoidance": avoid,
                    "desired_level": desired,
                    "place_value": value,
                    "utility": utility,
                    "weight": avoid or weight,
                    "compared": utility is not None,
                    "visual_comparison": visual_parts,
                    "evidence_ids": sorted(
                        {eid for c in facet.contributions for eid in c.evidence_ids}
                    )
                    if value is not None
                    else [],
                    "rule": "CONFIRMED_VISUAL_FACET_MATCH"
                    if owns_visual
                    else "EXPLICIT_AVOIDANCE"
                    if avoid
                    else "EXPLICIT_INTENSITY_MATCH"
                    if desired is not None
                    else "EXPECTED_EXPERIENCE_FULFILLMENT",
                }
            )
        if not reason and (known_weight == 0 or known_weight * 2 < total_weight):
            reason = "INSUFFICIENT_EXPECTATION_COVERAGE"
        if reason:
            excluded.append({"place_id": place.place_id, "reason": reason})
            continue
        numerator = sum(c["utility"] * c["weight"] for c in components if c["utility"] is not None)
        score = half_up(numerator, known_weight)
        scored.append(
            {
                "place_id": place.place_id,
                "name_ko": place.name_ko,
                "region_name": place.region_name,
                "category": place.category,
                "assessment_sha256": assessment.assessment_sha256,
                "duplicate_group_id": place.duplicate_group_id,
                "score": score,
                "coverage": {
                    "known_weight": known_weight,
                    "total_weight": total_weight,
                    "percent": half_up(100 * known_weight, total_weight),
                },
                "axes": {k: a.value for k, a in axes.items()},
                "components": components,
                "warnings": ["MISSING_EXPECTATION_EVIDENCE"] if known_weight < total_weight else [],
            }
        )
    ordered = sorted(scored, key=lambda r: (-r["score"], r["place_id"]))

    def compatible(left: dict[str, Any], right: dict[str, Any]) -> bool:
        return (
            left["duplicate_group_id"] != right["duplicate_group_id"]
            and frozenset((left["place_id"], right["place_id"])) not in forbidden
        )

    def completion(pool: list[dict[str, Any]], need: int) -> list[dict[str, Any]] | None:
        if need == 0:
            return []
        if len({c["duplicate_group_id"] for c in pool}) < need:
            return None
        for index, candidate in enumerate(pool):
            rest = [r for r in pool[index + 1 :] if compatible(candidate, r)]
            found = completion(rest, need - 1)
            if found is not None:
                return [candidate, *found]
        return None

    chosen: list[dict[str, Any]] = []
    for target in range(min(limit, len(ordered)), 0, -1):
        found = completion(ordered, target)
        if found is not None:
            chosen = found
            break
    selected = [row | {"rank": index + 1} for index, row in enumerate(chosen)]
    payload = {
        "schema_version": "authenticity-recommendation-run.v1",
        "ranking_version": RANKING_VERSION,
        "request_id": request_id or intent.submission.request_id,
        "intent_sha256": intent.intent_sha256,
        "profile_id": intent.profile_id,
        "candidate_membership_sha256": canonical_sha256(sorted(ids)),
        "assessment_set_sha256": canonical_sha256(sorted(a.assessment_sha256 for a in assessments)),
        "policy_sha256": next(iter(policy_hashes)) if policy_hashes else None,
        "visual_reference_sha256": canonical_sha256(
            {pid: r.bundle_sha256 for pid, r in sorted((visual_references or {}).items())}
        ),
        "requested_count": limit,
        "result_count": len(selected),
        "state": "COMPLETE" if len(selected) == limit else "LIMITED" if selected else "EMPTY",
        "items": selected,
        "exclusions": excluded,
        "eligible_count": len(scored),
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
        "validation_scope": "AUTOMATIC_RULES_AND_AI_REVIEW_ONLY",
    }
    payload["run_sha256"] = canonical_sha256(payload)
    return payload
