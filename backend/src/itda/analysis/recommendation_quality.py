"""Provider-free development comparisons; authored cases are not human validation.

The comparison policies are experiments, not aliases for the deployed kernel.
Release consistency separately invokes the real recommendation kernel.
"""

from __future__ import annotations

import copy
import math
import random
from collections import Counter
from datetime import datetime
from typing import Annotated, Any, Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Score100, Sha256, StableId, StrictContract, Version, require_utc
from itda.contracts.mvp_daily_refresh import DailyScoredRelease, parse_daily_scored_release
from itda.domain.canonical import canonical_sha256

EVALUATOR_VERSION = "recommendation-quality-evaluator-v1"
REPORT_SCHEMA_VERSION = "recommendation-quality-report.v1"
CONDITION_NAMES = (
    "visit_date_time",
    "companions",
    "transport",
    "walking",
    "indoor_outdoor",
    "crowd",
)
CONDITION_WEIGHTS = (400, 350, 350, 350, 300, 250)
AxisValues = tuple[Score100, Score100, Score100]
ConditionValues = tuple[
    Score100 | None,
    Score100 | None,
    Score100 | None,
    Score100 | None,
    Score100 | None,
    Score100 | None,
]
Purpose = Literal["SIGHTSEEING", "FOOD", "LODGING", "EXPERIENCE", "MIXED"]
EMPTY_CONDITIONS: ConditionValues = (None, None, None, None, None, None)


class QualityEvaluationError(ValueError):
    """Evaluation inputs cannot establish the stated development authority."""


def _reject_blind(value: object) -> None:
    # Reject before constructing/ranking scenarios, including nested membership metadata.
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in {"blind", "blind_members", "blind_membership"}:
                raise QualityEvaluationError("BLIND_INPUT_FORBIDDEN")
            _reject_blind(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _reject_blind(child)
    elif isinstance(value, str) and (
        value.upper() in {"BLIND", "BLIND-12"} or value.lower().startswith("blind:")
    ):
        raise QualityEvaluationError("BLIND_INPUT_FORBIDDEN")


class EvaluationCandidate(StrictContract):
    place_id: StableId
    split: Literal["DEV", "SYNTHETIC"]
    axes: AxisValues
    conditions: ConditionValues = EMPTY_CONDITIONS
    purpose: Purpose = "SIGHTSEEING"
    category: str | None = None
    region: str | None = None
    available: Annotated[bool, Field(strict=True)] | None = None
    evidence_count: Annotated[int, Field(strict=True, ge=0)] = 0
    total_claims: Annotated[int, Field(strict=True, ge=0)] = 0
    bound_claims: Annotated[int, Field(strict=True, ge=0)] = 0
    display_text: str = ""
    confidence: Score100 = 50

    @model_validator(mode="after")
    def validate_evidence(self) -> Self:
        if self.bound_claims > self.total_claims or (self.bound_claims and not self.evidence_count):
            raise ValueError("bound claims require source evidence and cannot exceed total claims")
        return self


class ComparisonPolicy(StrictContract):
    policy_id: Version
    interpretation: Literal["distance", "importance"]
    experience_weight_bp: Annotated[int, Field(strict=True, ge=0, le=10_000)] = 8_000
    condition_weight_bp: Annotated[int, Field(strict=True, ge=0, le=10_000)] = 2_000
    diversity_weight_bp: Annotated[int, Field(strict=True, ge=0, le=10_000)] = 0

    @model_validator(mode="after")
    def validate_weights(self) -> Self:
        if self.experience_weight_bp + self.condition_weight_bp != 10_000:
            raise ValueError("experience/condition weights must sum to 10000")
        return self


class DevelopmentScenario(StrictContract):
    scenario_id: Version
    split: Literal["DEV"]
    input_kind: Literal["SYNTHETIC", "OBSERVED"]
    description_ko: str
    axes: AxisValues
    conditions: ConditionValues = EMPTY_CONDITIONS
    condition_maxima: ConditionValues = EMPTY_CONDITIONS
    purpose: Purpose = "MIXED"
    candidates: Annotated[tuple[EvaluationCandidate, ...], Field(min_length=2, max_length=100)]
    expected_first: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_membership(self) -> Self:
        ids = [row.place_id for row in self.candidates]
        if len(ids) != len(set(ids)):
            raise ValueError("candidate IDs must be unique")
        expected_split = "SYNTHETIC" if self.input_kind == "SYNTHETIC" else "DEV"
        if any(row.split != expected_split for row in self.candidates):
            raise ValueError("mixed candidate split/input provenance forbidden")
        if self.input_kind == "OBSERVED" and self.expected_first:
            raise ValueError("authored expected order cannot be an observed relevance label")
        if any(place_id not in ids for place_id in self.expected_first.values()):
            raise ValueError("expected first must belong to candidate membership")
        return self


class DevelopmentSuite(StrictContract):
    schema_version: Literal["recommendation-development-scenarios.v1"]
    suite_version: Version
    split: Literal["DEV"]
    provenance: Literal["SYNTHETIC_BEHAVIORAL_CASES", "DEVELOPMENT_OBSERVATIONS"]
    seed: Annotated[int, Field(strict=True, ge=0, le=2**32 - 1)]
    policies: Annotated[tuple[ComparisonPolicy, ...], Field(min_length=1, max_length=16)]
    scenarios: Annotated[tuple[DevelopmentScenario, ...], Field(min_length=1, max_length=100)]

    @model_validator(mode="after")
    def validate_provenance(self) -> Self:
        for values in (
            [row.policy_id for row in self.policies],
            [row.scenario_id for row in self.scenarios],
        ):
            if len(values) != len(set(values)):
                raise ValueError("scenario and policy IDs must be unique")
        expected = "SYNTHETIC" if self.provenance == "SYNTHETIC_BEHAVIORAL_CASES" else "OBSERVED"
        if any(row.input_kind != expected for row in self.scenarios):
            raise ValueError("mixed scenario provenance forbidden")
        policy_ids = {policy.policy_id for policy in self.policies}
        if any(set(row.expected_first) - policy_ids for row in self.scenarios):
            raise ValueError("expected order references unknown policy")
        return self


class RelevanceJudgment(StrictContract):
    scenario_id: Version
    place_id: StableId
    split: Literal["DEV"]
    relevance: Annotated[int, Field(strict=True, ge=0, le=3)]


class HumanJudgments(StrictContract):
    schema_version: Literal["recommendation-human-judgments.v1"]
    split: Literal["DEV"]
    source_kind: Literal["HUMAN_RELEVANCE"]
    collection_id: StableId
    protocol_version: Version
    collected_at: datetime
    source_sha256: Sha256
    scenario_suite_sha256: Sha256
    genuine_human_collection_attested: Annotated[bool, Field(strict=True)]
    labels: Annotated[tuple[RelevanceJudgment, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_collection(self) -> Self:
        require_utc(self.collected_at, field_name="collected_at")
        if self.genuine_human_collection_attested is not True:
            raise ValueError("genuine human collection must be explicitly attested")
        ids = [(row.scenario_id, row.place_id) for row in self.labels]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate human judgments")
        return self


def ndcg_at_k(ranking: tuple[str, ...], labels: dict[str, int], k: int = 5) -> float | None:
    """Exponential gain; unjudged candidates are never assumed irrelevant."""
    if k < 1 or len(ranking) != len(set(ranking)):
        raise QualityEvaluationError("NDCG_RANKING_INVALID")
    if any(type(value) is not int or not 0 <= value <= 3 for value in labels.values()):
        raise QualityEvaluationError("NDCG_LABEL_INVALID")
    if set(ranking) - set(labels):
        raise QualityEvaluationError("NDCG_UNJUDGED_CANDIDATE")

    def dcg(values: list[int]) -> float:
        return float(
            sum((2**value - 1) / math.log2(index + 2) for index, value in enumerate(values[:k]))
        )

    ideal = dcg(sorted(labels.values(), reverse=True))
    if ideal == 0:
        return None
    return round(dcg([labels[place_id] for place_id in ranking]) / ideal, 8)


def _condition_fit(candidate: EvaluationCandidate, scenario: DevelopmentScenario) -> float | None:
    active = [
        (100 - abs(expected - actual), weight)
        for expected, actual, weight in zip(
            scenario.conditions, candidate.conditions, CONDITION_WEIGHTS, strict=True
        )
        if expected is not None and actual is not None
    ]
    if not active:
        return None
    return sum(fit * weight for fit, weight in active) / sum(weight for _, weight in active)


def _base_score(
    candidate: EvaluationCandidate, scenario: DevelopmentScenario, policy: ComparisonPolicy
) -> float:
    if policy.interpretation == "distance":
        experience = (
            sum(
                100 - abs(wanted - actual)
                for wanted, actual in zip(scenario.axes, candidate.axes, strict=True)
            )
            / 3
        )
    else:
        total = sum(scenario.axes)
        experience = (
            sum(
                weight * actual
                for weight, actual in zip(scenario.axes, candidate.axes, strict=True)
            )
            / total
            if total
            else sum(candidate.axes) / 3
        )
    conditions = _condition_fit(candidate, scenario)
    if conditions is None:
        return experience
    return (
        experience * policy.experience_weight_bp + conditions * policy.condition_weight_bp
    ) / 10_000


def _exclusion(candidate: EvaluationCandidate, scenario: DevelopmentScenario) -> str | None:
    if candidate.available is False:
        return "UNAVAILABLE"
    if scenario.purpose != "MIXED" and candidate.purpose != scenario.purpose:
        return "PURPOSE_MISMATCH"
    if any(
        maximum is not None and actual is not None and actual > maximum
        for maximum, actual in zip(scenario.condition_maxima, candidate.conditions, strict=True)
    ):
        return "KNOWN_CONDITION_VIOLATION"
    return None


def _rank(scenario: DevelopmentScenario, policy: ComparisonPolicy) -> list[dict[str, Any]]:
    remaining = [row for row in scenario.candidates if _exclusion(row, scenario) is None]
    selected: list[EvaluationCandidate] = []
    output: list[dict[str, Any]] = []
    while remaining and len(output) < 5:
        scored: list[tuple[float, float, str, EvaluationCandidate]] = []
        for row in remaining:
            relevance = _base_score(row, scenario, policy)
            novelty = min(
                (
                    sum(abs(a - b) for a, b in zip(row.axes, prior.axes, strict=True)) / 3
                    for prior in selected
                ),
                default=100.0,
            )
            combined = (
                relevance * (10_000 - policy.diversity_weight_bp)
                + novelty * policy.diversity_weight_bp
            ) / 10_000
            scored.append((-combined, -relevance, row.place_id, row))
        winner = min(scored, key=lambda row: row[:3])
        selected.append(winner[3])
        output.append(
            {
                "place_id": winner[2],
                "score": round(-winner[0], 6),
                "relevance_score": round(-winner[1], 6),
            }
        )
        remaining = [row for row in remaining if row.place_id != winner[2]]
    return output


def _policy_report(
    scenario: DevelopmentScenario, policy: ComparisonPolicy, labels: dict[str, int] | None
) -> dict[str, Any]:
    ranking = _rank(scenario, policy)
    by_id = {row.place_id: row for row in scenario.candidates}
    selected = [by_id[row["place_id"]] for row in ranking]
    count = len(selected)
    requested = [index for index, value in enumerate(scenario.conditions) if value is not None]
    observed_pairs = sum(
        row.conditions[index] is not None for row in selected for index in requested
    )
    possible_pairs = count * len(requested)
    total_claims = sum(row.total_claims for row in selected)
    bound_claims = sum(row.bound_claims for row in selected)
    ids = tuple(row.place_id for row in selected)
    # Relevance is evaluated within the same explicitly eligible candidate set.
    eligible_labels = (
        {
            row.place_id: labels[row.place_id]
            for row in scenario.candidates
            if _exclusion(row, scenario) is None
        }
        if labels is not None
        else None
    )
    ndcg = ndcg_at_k(ids, eligible_labels) if eligible_labels is not None else None
    return {
        "ranking": ranking,
        "ndcg_at_5": ndcg,
        "ndcg_status": "unavailable"
        if labels is None
        else ("no_relevant_labels" if ndcg is None else "available"),
        "unavailable_inclusion_rate": sum(row.available is False for row in selected) / count
        if count
        else None,
        "purpose_violation_rate": sum(
            scenario.purpose != "MIXED" and row.purpose != scenario.purpose for row in selected
        )
        / count
        if count
        else None,
        "condition_violation_rate": sum(
            _exclusion(row, scenario) == "KNOWN_CONDITION_VIOLATION" for row in selected
        )
        / count
        if count
        else None,
        "unknown_availability_count": sum(row.available is None for row in selected),
        "unknown_condition_rate": (1 - observed_pairs / possible_pairs) if possible_pairs else None,
        "category_composition": dict(
            sorted(Counter(row.category or "UNKNOWN" for row in selected).items())
        ),
        "region_composition": dict(
            sorted(Counter(row.region or "UNKNOWN" for row in selected).items())
        ),
        "distinct_known_categories": len({row.category for row in selected if row.category}),
        "distinct_known_regions": len({row.region for row in selected if row.region}),
        "evidence": {
            "claims": total_claims,
            "source_bound_claims": bound_claims,
            "source_binding_coverage": bound_claims / total_claims if total_claims else None,
            "entailment_review": "unavailable",
        },
        "exclusions": {
            row.place_id: reason
            for row in scenario.candidates
            if (reason := _exclusion(row, scenario)) is not None
        },
    }


def evaluate_scenarios(
    scenario_suite: dict[str, Any], *, judgments: dict[str, Any] | None = None
) -> dict[str, Any]:
    _reject_blind(scenario_suite)
    suite = DevelopmentSuite.model_validate(scenario_suite)
    suite_hash = canonical_sha256(scenario_suite)
    label_maps: dict[str, dict[str, int]] = {}
    relevance: dict[str, Any] = {
        "status": "unavailable",
        "reason": "NO_GENUINE_RELEVANCE_JUDGMENTS",
    }
    if judgments is not None:
        _reject_blind(judgments)
        supplied = HumanJudgments.model_validate(judgments)
        if suite.provenance != "DEVELOPMENT_OBSERVATIONS":
            raise QualityEvaluationError("SYNTHETIC_CASES_CANNOT_HAVE_HUMAN_RELEVANCE")
        if supplied.scenario_suite_sha256 != suite_hash:
            raise QualityEvaluationError("JUDGMENT_SCENARIO_BINDING_MISMATCH")
        expected = {
            (scenario.scenario_id, row.place_id)
            for scenario in suite.scenarios
            for row in scenario.candidates
        }
        actual = {(row.scenario_id, row.place_id) for row in supplied.labels}
        if actual != expected:
            raise QualityEvaluationError("JUDGMENTS_REQUIRE_EXACT_COMPLETE_MEMBERSHIP")
        for row in supplied.labels:
            label_maps.setdefault(row.scenario_id, {})[row.place_id] = row.relevance
        relevance = {
            "status": "available",
            "collection_id": supplied.collection_id,
            "protocol_version": supplied.protocol_version,
            "collected_at": supplied.collected_at.isoformat(),
            "source_sha256": supplied.source_sha256,
            "judgments_sha256": canonical_sha256(judgments),
            "provenance_validation": "SUPPLIER_ATTESTED_NOT_INDEPENDENTLY_VERIFIED",
        }
    cases = []
    for scenario in suite.scenarios:
        policies = {
            policy.policy_id: _policy_report(scenario, policy, label_maps.get(scenario.scenario_id))
            for policy in suite.policies
        }
        shuffled = list(scenario.candidates)
        random.Random(suite.seed).shuffle(shuffled)
        variants = {
            "candidate_order": scenario.model_copy(update={"candidates": tuple(shuffled)}),
            "display_whitespace": scenario.model_copy(
                update={
                    "candidates": tuple(
                        row.model_copy(
                            update={"display_text": row.display_text.replace(" ", "") + "   "}
                        )
                        for row in scenario.candidates
                    )
                }
            ),
            "confidence_neutrality": scenario.model_copy(
                update={
                    "candidates": tuple(
                        row.model_copy(update={"confidence": (row.confidence + 53) % 101})
                        for row in scenario.candidates
                    )
                }
            ),
        }
        checks = {
            name: all(
                _rank(variant, policy) == policies[policy.policy_id]["ranking"]
                for policy in suite.policies
            )
            for name, variant in variants.items()
        }
        expected_checks = {
            policy_id: bool(policies[policy_id]["ranking"])
            and policies[policy_id]["ranking"][0]["place_id"] == expected
            for policy_id, expected in scenario.expected_first.items()
        }
        cases.append(
            {
                "scenario_id": scenario.scenario_id,
                "input_kind": scenario.input_kind,
                "policies": policies,
                "invariance": {"passed": all(checks.values()), "checks": checks},
                "synthetic_expected_order": expected_checks,
            }
        )
    return {
        "evaluator_version": EVALUATOR_VERSION,
        "scenario_suite_sha256": suite_hash,
        "split": "DEV",
        "provenance": suite.provenance,
        "seed": suite.seed,
        "policies": [row.model_dump(mode="json") for row in suite.policies],
        "human_relevance": relevance,
        "scenarios": cases,
        "promotion_decision": "NONE_COMPARISON_ONLY",
        "comparison_scope": "EXPERIMENTAL_SCORERS_SAME_ELIGIBLE_CANDIDATES_NOT_PRODUCTION_REPLAY",
    }


def _synthetic_candidate(place_id: str, axes: list[int], **values: Any) -> dict[str, Any]:
    return {"place_id": "synthetic:" + place_id, "split": "SYNTHETIC", "axes": axes, **values}


DEFAULT_SCENARIO_SUITE: dict[str, Any] = {
    "schema_version": "recommendation-development-scenarios.v1",
    "suite_version": "development-scenarios-v1",
    "split": "DEV",
    "provenance": "SYNTHETIC_BEHAVIORAL_CASES",
    "seed": 20260908,
    "policies": [
        {"policy_id": "distance", "interpretation": "distance"},
        {"policy_id": "importance", "interpretation": "importance"},
        {
            "policy_id": "importance-conditions-40",
            "interpretation": "importance",
            "experience_weight_bp": 6000,
            "condition_weight_bp": 4000,
        },
    ],
    "scenarios": [
        {
            "scenario_id": "balanced-interpretation",
            "split": "DEV",
            "input_kind": "SYNTHETIC",
            "description_ko": (
                "균형 취향의 중요도와 원하는 강도 해석 비교. 실제 선호 라벨이 아니다."
            ),
            "axes": [33, 40, 36],
            "candidates": [
                _synthetic_candidate("quiet-low", [30, 40, 35]),
                _synthetic_candidate("rich-high", [80, 80, 80]),
                _synthetic_candidate("history", [90, 20, 20]),
                _synthetic_candidate("emotion", [20, 90, 20]),
                _synthetic_candidate("rest", [20, 20, 90]),
                _synthetic_candidate("middle", [50, 50, 50]),
            ],
            "expected_first": {
                "distance": "synthetic:quiet-low",
                "importance": "synthetic:rich-high",
            },
        },
        {
            "scenario_id": "purpose-and-access",
            "split": "DEV",
            "input_kind": "SYNTHETIC",
            "description_ko": "방문 불가·목적 불일치·확인된 보행 제약 제외와 미확인 조건 보존.",
            "axes": [50, 50, 50],
            "purpose": "SIGHTSEEING",
            "conditions": [None, None, None, 25, None, 20],
            "condition_maxima": [None, None, None, 50, None, None],
            "candidates": [
                _synthetic_candidate("unknown", [70, 70, 70], category="관광지", region="중심"),
                _synthetic_candidate(
                    "flat",
                    [60, 70, 80],
                    conditions=[None, None, None, 20, None, 20],
                    evidence_count=1,
                    total_claims=3,
                    bound_claims=2,
                    category="자연",
                    region="외곽",
                ),
                _synthetic_candidate("closed", [100, 100, 100], available=False),
                _synthetic_candidate("hotel", [100, 100, 100], purpose="LODGING"),
                _synthetic_candidate(
                    "steep", [100, 100, 100], conditions=[None, None, None, 90, None, None]
                ),
            ],
        },
        {
            "scenario_id": "weights-tradeoff",
            "split": "DEV",
            "input_kind": "SYNTHETIC",
            "description_ko": (
                "역사 경험과 확인된 보행 조건의 비중 비교. 가중치를 자동 승격하지 않는다."
            ),
            "axes": [100, 0, 0],
            "conditions": [None, None, None, 0, None, None],
            "candidates": [
                _synthetic_candidate(
                    "history-demanding",
                    [100, 30, 30],
                    conditions=[None, None, None, 60, None, None],
                ),
                _synthetic_candidate(
                    "history-accessible", [70, 40, 40], conditions=[None, None, None, 0, None, None]
                ),
                _synthetic_candidate(
                    "other", [20, 90, 90], conditions=[None, None, None, 0, None, None]
                ),
            ],
            "expected_first": {
                "importance": "synthetic:history-demanding",
                "importance-conditions-40": "synthetic:history-accessible",
            },
        },
    ],
}
DEFAULT_SCENARIO_SUITE_SHA256 = canonical_sha256(DEFAULT_SCENARIO_SUITE)


def audit_public_release(
    release: DailyScoredRelease, *, previous_release: DailyScoredRelease | None = None
) -> dict[str, Any]:
    """Audit source bindings; source existence alone never establishes entailment."""
    from itda.pipeline.place_facts import resolve_profile_conditions

    fact_counts: Counter[str] = Counter()
    unknown_fields: Counter[str] = Counter()
    for profile in release.profiles:
        resolved = resolve_profile_conditions(profile)
        for key, fact in resolved.facts.observations.items():
            fact_counts[fact.state] += 1
            if fact.state == "UNKNOWN":
                unknown_fields[key] += 1
    lengths = sorted(
        len(excerpt.excerpt_ko) for row in release.profiles for excerpt in row.evidence_excerpts
    )
    claims = sum(len(row.scores.justifications) for row in release.profiles)
    bound = sum(
        bool(justification.evidence_ids)
        and set(justification.evidence_ids).issubset(set(row.source_evidence_ids))
        for row in release.profiles
        for justification in row.scores.justifications
    )
    drift = None
    if previous_release is not None:
        previous = {row.place_id: row for row in previous_release.profiles}
        changes = [
            {
                "place_id": row.place_id,
                "max_axis_delta": max(
                    abs(getattr(row.scores, axis) - getattr(previous[row.place_id].scores, axis))
                    for axis in ("H", "E", "R")
                ),
            }
            for row in release.profiles
            if row.place_id in previous
        ]
        drift = {
            "previous_release_sha256": previous_release.release_sha256,
            "matched_profiles": len(changes),
            "axis_changes": changes,
            "max_axis_delta": max((row["max_axis_delta"] for row in changes), default=None),
            "new_place_ids": [
                row.place_id for row in release.profiles if row.place_id not in previous
            ],
        }
    return {
        "split": "PUBLIC",
        "use": "SOURCE_AND_CONSISTENCY_AUDIT_ONLY",
        "profile_count": len(release.profiles),
        "source_excerpt_count": len(lengths),
        "median_excerpt_characters": (
            (lengths[(len(lengths) - 1) // 2] + lengths[len(lengths) // 2]) / 2 if lengths else None
        ),
        "claim_count": claims,
        "source_bound_claim_count": bound,
        "source_binding_coverage": bound / claims if claims else None,
        "entailment_review": "unavailable",
        "human_relevance": "unavailable",
        "fact_state_counts": dict(sorted(fact_counts.items())),
        "unknown_fact_fields": dict(sorted(unknown_fields.items())),
        "low_confidence_review_count": sum(row.scores.confidence < 55 for row in release.profiles),
        "drift": drift,
    }


def build_release_consistency_report(
    release: DailyScoredRelease,
    *,
    kernel_version: str,
    projection_version: str,
    policy_version: str,
    scenario_suite: dict[str, Any] | None = None,
    previous_release: DailyScoredRelease | None = None,
) -> dict[str, Any]:
    """Bind synthetic invariants and actual-kernel checks to one immutable PUBLIC release."""
    from itda.contracts.mvp_scored_release import MvpScoredProfile
    from itda.contracts.place_facts import PLACE_FACT_POLICY_VERSION
    from itda.contracts.recommendation import (
        QUALITY_RECOMMENDATION_CONFIG,
        PublicRelationAuthority,
        RecommendationPurpose,
        RecommendationQualityContext,
    )
    from itda.domain.mvp_recommendation import (
        MvpRecommendationError,
        RankedMvpPlace,
        rank_mvp_top_five,
    )
    from itda.domain.recommendation_projection import RECOMMENDATION_PROJECTION_VERSION_V3

    # Revalidate nested hashes even if a caller constructed models through model_copy.
    release = parse_daily_scored_release(release.model_dump(mode="json"))
    suite = copy.deepcopy(DEFAULT_SCENARIO_SUITE if scenario_suite is None else scenario_suite)
    synthetic = evaluate_scenarios(suite)
    checks: list[dict[str, Any]] = [
        {
            "name": "executed_algorithm_versions",
            "passed": (
                kernel_version == QUALITY_RECOMMENDATION_CONFIG.kernel_version
                and projection_version == RECOMMENDATION_PROJECTION_VERSION_V3
                and policy_version == PLACE_FACT_POLICY_VERSION
            ),
            "detail": "requested binding matches imported production algorithm versions",
        },
        {
            "name": "development_invariants",
            "passed": all(row["invariance"]["passed"] for row in synthetic["scenarios"]),
            "detail": "candidate order, display whitespace, confidence",
        },
        {
            "name": "synthetic_expected_order",
            "passed": all(
                all(row["synthetic_expected_order"].values()) for row in synthetic["scenarios"]
            ),
            "detail": "authored behavior assertions, not human relevance",
        },
    ]
    relation = PublicRelationAuthority(
        relation_sha256=release.relation_sha256,
        place_ids=tuple(row.place_id for row in release.profiles),
        pairs=release.relation_pairs,
    )
    context = RecommendationQualityContext(
        companion="SOLO",
        transport="WALK_OR_TRANSIT",
        purpose=RecommendationPurpose.MIXED,
        eligible_place_ids=relation.place_ids,
    )

    def run_kernel(
        profiles: tuple[MvpScoredProfile, ...],
        axes: tuple[int, int, int],
        *,
        legacy: bool = False,
    ) -> tuple[RankedMvpPlace, ...]:
        try:
            return rank_mvp_top_five(
                profiles,
                relation_authority=relation,
                axis_targets=axes,
                condition_targets=(50, 50, 50, 50, 50, 50) if legacy else EMPTY_CONDITIONS,
                quality_context=None if legacy else context,
            )
        except MvpRecommendationError as error:
            checks.append({"name": "live_kernel_failure", "passed": False, "detail": str(error)})
            return ()

    samples = []
    for axes in ((33, 40, 36), (100, 0, 0), (0, 0, 100)):
        first = run_kernel(release.profiles, axes)
        reversed_result = run_kernel(tuple(reversed(release.profiles)), axes)
        checks.append(
            {
                "name": "live_kernel_candidate_order_" + "_".join(map(str, axes)),
                "passed": first == reversed_result,
                "detail": "same corrected production kernel",
            }
        )
        checks.append(
            {
                "name": "live_kernel_bounded_" + "_".join(map(str, axes)),
                "passed": len(first) == 5
                and all(
                    0 <= value <= 100
                    for row in first
                    for value in (row.relevance_score, row.novelty_score, row.combined_score)
                ),
                "detail": "five results and finite 0–100 scores",
            }
        )
        altered = tuple(
            row.model_copy(
                update={
                    "place_name_ko": row.place_name_ko.replace(" ", "") + "   ",
                    "scores": row.scores.model_copy(
                        update={"confidence": (row.scores.confidence + 53) % 101}
                    ),
                }
            )
            for row in release.profiles
        )
        altered_ranking = run_kernel(altered, axes)
        checks.append(
            {
                "name": "live_kernel_metadata_invariance_" + "_".join(map(str, axes)),
                "passed": first == altered_ranking,
                "detail": "in-memory name/confidence changes; never persisted or activated",
            }
        )
        selected_ids = [row.place_id for row in first]
        by_id = {row.place_id: row for row in release.profiles}
        checks.append(
            {
                "name": "live_kernel_relation_constraints_" + "_".join(map(str, axes)),
                "passed": len({by_id[place_id].duplicate_group_id for place_id in selected_ids})
                == len(first)
                and not any(
                    relation.forbids(left, right)
                    for index, left in enumerate(selected_ids)
                    for right in selected_ids[index + 1 :]
                ),
                "detail": "unique duplicate groups and no forbidden pair in Top5",
            }
        )
        legacy = run_kernel(release.profiles, axes, legacy=True)
        samples.append(
            {
                "axes": list(axes),
                "ranking": [row.place_id for row in first],
                "legacy_reference": {
                    "kernel_version": "recommendation-kernel-v3",
                    "condition_targets": [50] * 6,
                    "ranking": [row.place_id for row in legacy],
                    "top5_overlap_count": len(
                        {row.place_id for row in first} & {row.place_id for row in legacy}
                    ),
                    "interpretation": "legacy midpoint versus corrected unrequested conditions",
                },
            }
        )
    audit = audit_public_release(release, previous_release=previous_release)
    audit["live_kernel_samples"] = samples
    body = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "evaluator_version": EVALUATOR_VERSION,
        "binding": {
            "release_sha256": release.release_sha256,
            "kernel_version": kernel_version,
            "projection_version": projection_version,
            "policy_version": policy_version,
            "scenario_suite_sha256": canonical_sha256(suite),
        },
        "consistency": {
            "status": "pass" if all(row["passed"] for row in checks) else "fail",
            "checks": checks,
        },
        "human_relevance": {"status": "unavailable", "reason": "NO_GENUINE_RELEVANCE_JUDGMENTS"},
        "synthetic_evaluation": synthetic,
        "public_release_audit": audit,
    }
    return {**body, "report_sha256": canonical_sha256(body)}
