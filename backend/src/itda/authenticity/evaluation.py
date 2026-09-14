"""Source ablations and technical sensitivity, without invented relevance labels."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from itda.authenticity.batch import write_once
from itda.authenticity.contracts import Assessment
from itda.authenticity.intent import IntentSubmission, build_intent
from itda.authenticity.ranking import rank
from itda.authenticity.rubric import AXES, FACET_KEYS
from itda.authenticity.scoring import verify_assessment
from itda.domain.canonical import canonical_sha256
from itda.pipeline.destination_evidence import atomic_json

VERSION = "authenticity-technical-ablation-v1"
CONDITIONS = {
    "A0": "text",
    "A1": "photo-er",
    "A2": "photo-her",
    "A3": "social-count",
    "A4": "social-meaning",
}
EVALUATION_TIME = datetime(2026, 9, 11, tzinfo=UTC)


def scenarios() -> list[dict[str, Any]]:
    result = []
    for key in FACET_KEYS:
        for weight in (2, 4):
            result.append({"id": f"facet:{key}:importance:{weight}", "answers": {key: weight}})
    for axis in AXES:
        result.append({"id": "axis:" + axis, "answers": {k: 2 for k in FACET_KEYS if k[0] == axis}})
    result.append({"id": "all-moderate", "answers": dict.fromkeys(FACET_KEYS, 2)})
    result.append({"id": "all-required", "answers": dict.fromkeys(FACET_KEYS, 4)})
    result.append({"id": "history-and-rest", "answers": {"H.a": 2, "H.d": 2, "R.b": 2, "R.c": 2}})
    return result


def register(directory: Path) -> dict[str, Any]:
    manifest = json.loads((directory / "manifest.json").read_text())
    plan = {
        "version": VERSION,
        "manifest_sha256": manifest["manifest_sha256"],
        "conditions": CONDITIONS,
        "social_photo_condition": "A1",
        "scenario_origin": "AUTHORED_TECHNICAL_PROBES_NOT_HUMAN_PREFERENCES",
        "scenarios": scenarios(),
        "scope": "EXPLORATORY_DEVELOPMENT_TECHNICAL_COMPARISON",
        "metrics": [
            "recalculation_and_authority_violations",
            "unknown_facets",
            "axis_coverage",
            "eligible_candidates",
            "full_pool_top5_overlap",
            "common_eligible_top5_overlap",
            "region_category_cohort_photo_social_exposure",
        ],
        "not_measured": ["human_accuracy", "construct_validity", "user_satisfaction", "NDCG"],
        "human_evaluation": "EXCLUDED_BY_USER",
    }
    plan["plan_sha256"] = canonical_sha256(plan)
    write_once(directory / "evaluation/plan.json", plan)
    return plan


def overlap(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    first = [i["place_id"] for i in a["items"]]
    second = [i["place_id"] for i in b["items"]]
    union = set(first) | set(second)
    return {
        "first_count": len(first),
        "second_count": len(second),
        "same_order": first == second,
        "shared": len(set(first) & set(second)),
        "jaccard": round(len(set(first) & set(second)) / len(union), 4) if union else None,
        "first": first,
        "second": second,
    }


def evaluate(directory: Path) -> dict[str, Any]:
    plan = register(directory)
    manifest = json.loads((directory / "manifest.json").read_text())
    if manifest["manifest_sha256"] != canonical_sha256(
        {k: v for k, v in manifest.items() if k != "manifest_sha256"}
    ):
        raise ValueError("EVALUATION_MANIFEST_DIGEST_MISMATCH")
    ids = tuple(m["place_id"] for m in manifest["members"])
    conditions = {}
    for name, folder in CONDITIONS.items():
        rows = tuple(
            Assessment.model_validate_json(
                (
                    directory / "final-assessments" / folder / (pid.split(":")[-1] + ".json")
                ).read_bytes()
            )
            for pid in ids
        )
        if tuple(a.source.place.place_id for a in rows) != ids:
            raise ValueError("ABLATION_CANDIDATE_MEMBERSHIP_MISMATCH")
        for a in rows:
            verify_assessment(a)
        conditions[name] = rows
    # Assert actual paired interventions instead of merely naming five folders.
    for index, baseline in enumerate(conditions["A0"]):
        for condition, expected in {
            "A0": ("NONE", "NONE"),
            "A1": ("ER", "NONE"),
            "A2": ("HER_CONDITIONAL", "NONE"),
            "A3": ("ER", "COUNT"),
            "A4": ("ER", "COUNT_AND_MEANING"),
        }.items():
            policy = conditions[condition][index].policy
            if (policy.photo_mode, policy.social_mode) != expected:
                raise ValueError("ABLATION_CONDITION_POLICY_MISMATCH")
        official = {e.evidence_id: e for e in baseline.source.evidence}
        photos = {
            e.evidence_id: e
            for e in conditions["A1"][index].source.evidence
            if e.modality == "IMAGE"
        }
        for condition in ("A1", "A2", "A3", "A4"):
            evidence = {e.evidence_id: e for e in conditions[condition][index].source.evidence}
            if any(evidence.get(eid) != e for eid, e in official.items()):
                raise ValueError("ABLATION_CHANGED_OFFICIAL_SOURCE")
            if {eid: e for eid, e in evidence.items() if e.modality == "IMAGE"} != photos:
                raise ValueError("ABLATION_CHANGED_PHOTO_INPUT")
        for condition in ("A1", "A2", "A3"):
            if conditions[condition][index].judgments != baseline.judgments:
                raise ValueError("PHOTO_COUNT_ABLATION_CHANGED_TEXT_JUDGMENTS")
        for j, k in zip(baseline.judgments, conditions["A4"][index].judgments, strict=True):
            if j.key not in {"E.a", "E.b"} and j != k:
                raise ValueError("SOCIAL_MEANING_ABLATION_CHANGED_UNRELATED_FACET")
    social_plan = json.loads((directory / "social/plan.json").read_text())
    if social_plan["photo_condition"] != "photo-er":
        raise ValueError("EVALUATION_SOCIAL_PHOTO_POLICY_DIFFERS")
    profiles = [
        build_intent(
            IntentSubmission(
                request_id=s["id"], answers={k: s["answers"].get(k, 0) for k in FACET_KEYS}
            ),
            created_at=EVALUATION_TIME,
        )
        for s in plan["scenarios"]
    ]
    by_id = {a.source.place.place_id: a for a in conditions["A4"]}
    strata: dict[str, dict[str, str]] = {}
    for pid, a in by_id.items():
        counts = [
            e.reported_count
            for e in a.source.evidence
            if e.modality == "COUNT" and e.state == "AVAILABLE" and e.reported_count is not None
        ]
        strata[pid] = {
            "region": a.source.place.region_name.split()[0],
            "category": a.source.place.category,
            "cohort": a.source.place.cohort,
            "photo": "present"
            if any(e.modality == "IMAGE" for e in a.source.evidence)
            else "absent",
            "social_caption": "present"
            if any(
                e.receipt.provider == "APIFY_INSTAGRAM" and e.modality == "TEXT"
                for e in a.source.evidence
            )
            else "absent",
            "social_count": "unknown"
            if not counts
            else "under_1000"
            if counts[0] < 1000
            else "1000_to_99999"
            if counts[0] < 100000
            else "100000_plus",
        }
    exposure: dict[str, Any] = {}
    summaries = {}
    runs: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    eligibility: dict[str, dict[str, set[str]]] = defaultdict(dict)
    for condition, rows in conditions.items():
        shown: Counter[str] = Counter()
        available: Counter[str] = Counter()
        records = []
        for profile in profiles:
            result = rank(assessments=rows, intent=profile, created_at=EVALUATION_TIME)
            scenario = profile.submission.request_id
            runs[scenario][condition] = result
            excluded = {e["place_id"] for e in result["exclusions"]}
            eligible = set(ids) - excluded
            eligibility[scenario][condition] = eligible
            shown.update(i["place_id"] for i in result["items"])
            available.update(eligible)
            records.append(
                {
                    "scenario": scenario,
                    "eligible": len(eligible),
                    "results": result["result_count"],
                    "state": result["state"],
                    "exclusions": dict(Counter(e["reason"] for e in result["exclusions"])),
                    "run_sha256": result["run_sha256"],
                }
            )
        groups: dict[str, dict[str, Any]] = {}
        for dimension in next(iter(strata.values())):
            groups[dimension] = {}
            for label in sorted({s[dimension] for s in strata.values()}):
                members = [pid for pid in ids if strata[pid][dimension] == label]
                opportunities = sum(available[pid] for pid in members)
                appearances = sum(shown[pid] for pid in members)
                groups[dimension][label] = {
                    "places": len(members),
                    "eligible_opportunities": opportunities,
                    "top5_appearances": appearances,
                    "exposure_per_eligible_opportunity": round(appearances / opportunities, 4)
                    if opportunities
                    else None,
                }
        exposure[condition] = groups
        summaries[condition] = {
            "places": len(rows),
            "unknown_facets": sum(f.value is None for a in rows for f in a.facets),
            "total_facets": len(rows) * 12,
            "axis_coverage": {
                axis: sum(next(x for x in a.axes if x.axis == axis).value is not None for a in rows)
                for axis in AXES
            },
            "hard_violations": 0,
            "policy_sha256": rows[0].policy.policy_sha256,
            "scenarios": records,
        }
    comparisons = []
    for profile in profiles:
        scenario = profile.submission.request_id
        for first, second in (("A0", "A1"), ("A1", "A2"), ("A1", "A3"), ("A3", "A4"), ("A0", "A4")):
            common = eligibility[scenario][first] & eligibility[scenario][second]
            common_runs = [
                rank(
                    assessments=tuple(
                        a for a in conditions[c] if a.source.place.place_id in common
                    ),
                    intent=profile,
                    created_at=EVALUATION_TIME,
                )
                for c in (first, second)
            ]
            comparisons.append(
                {
                    "scenario": scenario,
                    "first": first,
                    "second": second,
                    "full_pool": overlap(runs[scenario][first], runs[scenario][second]),
                    "common_eligible_places": len(common),
                    "common_pool": overlap(*common_runs),
                }
            )
    result = {
        "version": VERSION,
        "plan_sha256": plan["plan_sha256"],
        "scope": plan["scope"],
        "human_evaluation": "EXCLUDED_BY_USER",
        "scenario_count": len(profiles),
        "conditions": summaries,
        "comparisons": comparisons,
        "exposure": exposure,
        "interpretation": [
            "수치 변화와 노출 차이는 기술적 관측이며 추천 품질·만족도 개선의 증거가 아니다.",
            "출처·재계산 위반 0은 인용 내용의 참이나 AI 판단의 의미 정확도를 보장하지 않는다.",
            "자료가 없는 장소의 누락과 자격 확대는 공통 후보 순위 변화와 따로 비교한다.",
            "SNS 결과는 유료 확대 없는 40곳 탐색 표본에만 한정된다.",
        ],
    }
    result["report_sha256"] = canonical_sha256(result)
    atomic_json(directory / "evaluation/results.json", result)
    atomic_json(directory / "evaluation/raw-runs.json", dict(runs))
    return result
