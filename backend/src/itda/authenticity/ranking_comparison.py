"""Post-freeze development check of importance and implicit intensity semantics."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from itda.authenticity.batch import write_once
from itda.authenticity.contracts import Assessment
from itda.authenticity.evaluation import EVALUATION_TIME, overlap, scenarios
from itda.authenticity.intent import Intent, IntentSubmission, build_intent
from itda.authenticity.ranking import rank
from itda.authenticity.report import checked
from itda.authenticity.rubric import FACET_KEYS
from itda.authenticity.scoring import verify_assessment
from itda.domain.canonical import canonical_sha256


def distance_profile(profile: Intent) -> Intent:
    """The comparator deliberately treats importance as a target unless explicit.

    This is an adapter of the old distance formula to the new facets, not a
    replay of the old questionnaire/axis pipeline or an actual user preference.
    """
    submission = profile.submission
    targets = dict(submission.desired_levels)
    for key, weight in submission.answers.items():
        if weight and key not in submission.avoid:
            targets.setdefault(key, weight)
    adapted = IntentSubmission.model_validate(
        submission.model_dump(mode="json") | {"desired_levels": targets}
    )
    return build_intent(adapted, created_at=profile.created_at)


def evaluate(directory: Path, repository: Path) -> dict[str, Any]:
    manifest = checked(directory / "manifest.json", "manifest_sha256")
    recipe = checked(directory / "evaluation/recipe.json", "recipe_sha256")
    if manifest.get("scope") != "EXPOSED_DEVELOPMENT" or len(manifest["members"]) != 120:
        raise ValueError("RANKING_COMPARISON_REQUIRES_EXPOSED_DEVELOPMENT_120")
    for file, digest in recipe["pipeline_code_sha256"].items():
        if hashlib.sha256((repository / file).read_bytes()).hexdigest() != digest:
            raise ValueError("RANKING_COMPARISON_FROZEN_CODE_CHANGED")
    rows = tuple(
        Assessment.model_validate_json(
            (
                directory / "final-assessments/text" / (m["place_id"].split(":")[-1] + ".json")
            ).read_bytes()
        )
        for m in manifest["members"]
    )
    if tuple(a.source.place.place_id for a in rows) != tuple(
        m["place_id"] for m in manifest["members"]
    ):
        raise ValueError("RANKING_COMPARISON_MEMBERSHIP_CHANGED")
    for assessment in rows:
        verify_assessment(assessment)
        if assessment.policy.photo_mode != "NONE" or assessment.policy.social_mode != "NONE":
            raise ValueError("RANKING_COMPARISON_REQUIRES_SAME_TEXT_ONLY_INPUT")
    probes = scenarios() + [
        {
            "id": f"explicit-intensity:R.b:{level}",
            "answers": {"R.b": 4},
            "desired_levels": {"R.b": level},
        }
        for level in (0, 2, 4)
    ]
    output = directory / "evaluation/ranking-comparison"
    previous = (
        json.loads((output / "plan.json").read_text()) if (output / "plan.json").exists() else {}
    )
    plan = {
        "version": "authenticity-ranking-comparison-v1",
        "registered_at": previous.get("registered_at", datetime.now(UTC).isoformat()),
        "scope": "POST_FREEZE_EXPLORATORY_DEVELOPMENT_NOT_CONFIRMATORY",
        "timing_deviation": "ORIGINAL_PLAN_REQUESTED_BEFORE_RECIPE_SELECTION_EXECUTED_AFTER_FREEZE",
        "manifest_sha256": manifest["manifest_sha256"],
        "frozen_recipe_sha256": recipe["recipe_sha256"],
        "assessment_hashes": sorted(a.assessment_sha256 for a in rows),
        "probes": probes,
        "conditions": {
            "FULFILLMENT": "Importance weights fulfillment; distance only for explicit intensity.",
            "IMPLICIT_DISTANCE": (
                "Same facets/weights/gates; absent intensity set to importance ×25."
            ),
        },
        "not_claimed": [
            "legacy_L0_end_to_end_replay",
            "user_preference",
            "human_quality",
            "optimal_formula",
            "independent_confirmation",
        ],
        "code_sha256": {
            str(p.relative_to(repository)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (
                repository / "backend/src/itda/authenticity/ranking_comparison.py",
                repository / "backend/src/itda/authenticity/ranking.py",
                repository / "backend/src/itda/domain/grounded_scoring.py",
            )
        },
    }
    plan["plan_sha256"] = canonical_sha256(plan)
    write_once(output / "plan.json", plan)
    runs = {}
    comparisons = []
    for probe in probes:
        profile = build_intent(
            IntentSubmission(
                request_id=probe["id"],
                answers={k: probe["answers"].get(k, 0) for k in FACET_KEYS},
                desired_levels=probe.get("desired_levels", {}),
            ),
            created_at=EVALUATION_TIME,
        )
        fulfillment = rank(assessments=rows, intent=profile, created_at=EVALUATION_TIME)
        distance = rank(
            assessments=rows, intent=distance_profile(profile), created_at=EVALUATION_TIME
        )
        if (
            fulfillment["candidate_membership_sha256"] != distance["candidate_membership_sha256"]
            or fulfillment["assessment_set_sha256"] != distance["assessment_set_sha256"]
            or fulfillment["exclusions"] != distance["exclusions"]
            or fulfillment["eligible_count"] != distance["eligible_count"]
        ):
            raise ValueError("RANKING_COMPARISON_CHANGED_CANDIDATES_OR_GATES")
        comparisons.append(
            {
                "scenario": probe["id"],
                "kind": "EXPLICIT_INTENSITY" if probe.get("desired_levels") else "IMPORTANCE_ONLY",
                "eligible": fulfillment["eligible_count"],
                "overlap": overlap(fulfillment, distance),
            }
        )
        runs[probe["id"]] = {"FULFILLMENT": fulfillment, "IMPLICIT_DISTANCE": distance}
    raw_payload = {"runs": runs}
    raw_sha = canonical_sha256(raw_payload)
    write_once(output / "raw-runs.json", raw_payload | {"report_sha256": raw_sha})
    groups = {}
    for kind in ("IMPORTANCE_ONLY", "EXPLICIT_INTENSITY"):
        members = [r for r in comparisons if r["kind"] == kind]
        groups[kind] = {
            "scenarios": len(members),
            "with_eligible_places": sum(r["eligible"] > 0 for r in members),
            "changed_top5_order": sum(not r["overlap"]["same_order"] for r in members),
        }
    result = {
        "plan_sha256": plan["plan_sha256"],
        "raw_runs_sha256": raw_sha,
        "scope": plan["scope"],
        "places": len(rows),
        "groups": groups,
        "comparisons": comparisons,
        "frozen_recipe_changed": False,
        "human_evaluation": "EXCLUDED_BY_USER",
        "interpretation_ko": [
            "새 항목·같은 텍스트·가중치·자격 필터에서 utility 해석만 비교했다.",
            "거리 비교 조건은 중요도를 목표 강도로 간주하는 의도적인 대조 조건이며 "
            "실제 사용자 의도가 아니다.",
            "옛 설문·옛 H/E/R·분위기·다양성까지 포함한 L0 전체 재생 실험은 아니다.",
            "기본식은 새 평가 전에 설계 판단으로 선택했다. "
            "이 비교는 이후 보완했으므로 선택 당시 근거나 확증으로 소급하지 않는다.",
            "기술적 순위 차이만 보고하며 품질 우월성·최적식·사람 만족도를 주장하지 않는다.",
        ],
    }
    result["report_sha256"] = canonical_sha256(result)
    write_once(output / "results.json", result)
    return result
