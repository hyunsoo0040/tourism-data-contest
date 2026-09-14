"""Frozen A0/A1 technical checks on new places, with exact observed denominators."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from itda.authenticity.batch import write_once
from itda.authenticity.contracts import Assessment, Policy
from itda.authenticity.evaluation import EVALUATION_TIME, overlap
from itda.authenticity.intent import IntentSubmission, build_intent
from itda.authenticity.ranking import rank
from itda.authenticity.rubric import AXES, FACET_KEYS
from itda.authenticity.scoring import verify_assessment
from itda.domain.canonical import canonical_sha256
from itda.pipeline.destination_evidence import atomic_json


def evaluate(directory: Path, repository: Path) -> dict[str, Any]:
    manifest = json.loads((directory / "manifest.json").read_text())
    recipe = json.loads((directory / "recipe.json").read_text())
    dev_plan = json.loads(
        (
            repository / "artifacts/authenticity-v1/20260911/development/evaluation/plan.json"
        ).read_text()
    )
    for obj, key in (
        (manifest, "manifest_sha256"),
        (recipe, "recipe_sha256"),
        (dev_plan, "plan_sha256"),
    ):
        if obj[key] != canonical_sha256({k: v for k, v in obj.items() if k != key}):
            raise ValueError("HELDOUT_PREREGISTERED_IDENTITY_CHANGED")
    if manifest["recipe_sha256"] != recipe["recipe_sha256"] or recipe["selected_condition"] != "A1":
        raise ValueError("HELDOUT_RECIPE_MISMATCH")
    for file, digest in recipe["pipeline_code_sha256"].items():
        if hashlib.sha256((repository / file).read_bytes()).hexdigest() != digest:
            raise ValueError("HELDOUT_SEMANTIC_RECIPE_CODE_CHANGED")
    plan = {
        "version": "authenticity-new-place-technical-evaluation-v1",
        "recipe_sha256": recipe["recipe_sha256"],
        "manifest_sha256": manifest["manifest_sha256"],
        "development_plan_sha256": dev_plan["plan_sha256"],
        "comparisons": ["A0", "A1"],
        "scenarios": dev_plan["scenarios"],
        "human_evaluation": "EXCLUDED_BY_USER",
    }
    plan["plan_sha256"] = canonical_sha256(plan)
    write_once(directory / "evaluation/plan.json", plan)
    conditions: dict[str, tuple[Assessment, ...]] = {}
    for name, folder in (("A0", "text"), ("A1", "photo-er")):
        collected_rows = []
        for member in manifest["members"]:
            a = Assessment.model_validate_json(
                (
                    directory
                    / "final-assessments"
                    / folder
                    / (member["place_id"].split(":")[-1] + ".json")
                ).read_bytes()
            )
            verify_assessment(a)
            if (
                a.source.place.place_id != member["place_id"]
                or a.source.place.cohort != "new-evaluation"
            ):
                raise ValueError("HELDOUT_SOURCE_MEMBERSHIP_CHANGED")
            expected = Policy() if name == "A0" else Policy.model_validate(recipe["policy"])
            if a.policy != expected:
                raise ValueError("HELDOUT_SCORING_POLICY_CHANGED")
            collected_rows.append(a)
        conditions[name] = tuple(collected_rows)
    if len(conditions["A0"]) != 60:
        raise ValueError("HELDOUT_TARGET_MEMBERSHIP_NOT_COMPLETE")
    for before, after in zip(conditions["A0"], conditions["A1"], strict=True):
        if before.judgments != after.judgments:
            raise ValueError("HELDOUT_PHOTOS_CHANGED_TEXT_JUDGMENTS")
        if before.axes[0] != after.axes[0]:
            raise ValueError("HELDOUT_A1_CHANGED_HISTORY_AXIS")
    checks = {}
    for name, rows in conditions.items():
        checks[name] = {
            "places": len(rows),
            "axis_coverage": {
                axis: sum(next(s for s in a.axes if s.axis == axis).value is not None for a in rows)
                for axis in AXES
            },
            "unknown_facets": sum(f.value is None for a in rows for f in a.facets),
            "hard_violations": 0,
            "photo_places": sum(
                any(e.modality == "IMAGE" for e in a.source.evidence) for a in rows
            ),
        }
    runs = []
    raw_runs = {}
    for scenario in plan["scenarios"]:
        intent = build_intent(
            IntentSubmission(
                request_id=scenario["id"],
                answers={k: scenario["answers"].get(k, 0) for k in FACET_KEYS},
            ),
            created_at=EVALUATION_TIME,
        )
        run_a, run_b = [
            rank(assessments=conditions[name], intent=intent, created_at=EVALUATION_TIME)
            for name in ("A0", "A1")
        ]
        excluded = {e["place_id"] for result in (run_a, run_b) for e in result["exclusions"]}
        common = [
            rank(
                assessments=tuple(
                    r for r in conditions[name] if r.source.place.place_id not in excluded
                ),
                intent=intent,
                created_at=EVALUATION_TIME,
            )
            for name in ("A0", "A1")
        ]
        raw_runs[scenario["id"]] = {
            "A0": run_a,
            "A1": run_b,
            "common_A0": common[0],
            "common_A1": common[1],
        }
        runs.append(
            {
                "scenario": scenario["id"],
                "full_pool": overlap(run_a, run_b),
                "common_pool": overlap(*common),
                "eligible": {"A0": run_a["eligible_count"], "A1": run_b["eligible_count"]},
                "exclusions": {
                    name: dict(Counter(e["reason"] for e in result["exclusions"]))
                    for name, result in (("A0", run_a), ("A1", run_b))
                },
            }
        )
    pixels = json.loads((directory / "photo-review/summary.json").read_text())
    semantics = json.loads((directory / "semantic-review/summary.json").read_text())
    report = {
        "version": plan["version"],
        "plan_sha256": plan["plan_sha256"],
        "recipe_sha256": recipe["recipe_sha256"],
        "scope": "NEW_PLACES_FROZEN_AUTOMATIC_AND_SAME_MODEL_AI_CHECKS",
        "executed_at": datetime.now(UTC).isoformat(),
        "scenario_reference_time": EVALUATION_TIME.isoformat(),
        "conditions": checks,
        "scenarios": runs,
        "observed_photo_images": pixels["images"],
        "photo_ai_decisions": pixels["decisions"],
        "text_ai_decisions": dict(
            Counter(
                d["decision"] for r in semantics["rows"] for d in r["semantic_review"]["reviews"]
            )
        ),
        "human_evaluation": "EXCLUDED_BY_USER",
        "quality_superiority": "NOT_ESTABLISHED",
        "limitations": [
            "관광사진 추가 수집은 Odii 일일 한도 중단 이후 재시도하지 않아 "
            "사진 표본은 목표60장보다 적다.",
            "선정된60곳의 기술 검사이며 전국의 모든 관광지나 실제 사람의 만족도를 대표하지 않는다.",
            "동일 모델의 별도 AI 검수는 독립된 사람 정답이 아니다. "
            "추천 순서 변화는 선호 개선이 아니다.",
        ],
    }
    report["report_sha256"] = canonical_sha256(report)
    atomic_json(directory / "evaluation/results.json", report)
    atomic_json(directory / "evaluation/raw-runs.json", raw_runs)
    return report
