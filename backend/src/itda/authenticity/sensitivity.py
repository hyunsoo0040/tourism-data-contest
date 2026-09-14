"""Paired missing-photo probes and exact-duplicate invariants, without new inference."""

from __future__ import annotations

import json
import random
from collections import Counter
from pathlib import Path
from typing import Any

from itda.authenticity.batch import write_once
from itda.authenticity.contracts import Assessment
from itda.authenticity.evaluation import EVALUATION_TIME, overlap, scenarios
from itda.authenticity.intent import IntentSubmission, build_intent
from itda.authenticity.ranking import rank
from itda.authenticity.rubric import FACET_KEYS
from itda.authenticity.scoring import build_assessment, verify_assessment
from itda.authenticity.sources import extend_source, seal_bundle, seal_evidence
from itda.domain.canonical import canonical_sha256
from itda.pipeline.destination_evidence import atomic_json


def values(a: Assessment) -> dict[str, int | None]:
    return {f.key: f.value for f in a.facets}


def evaluate(directory: Path) -> dict[str, Any]:
    manifest = json.loads((directory / "manifest.json").read_text())
    ids = tuple(m["place_id"] for m in manifest["members"])
    plan = {
        "version": "authenticity-source-sensitivity-v1",
        "manifest_sha256": manifest["manifest_sha256"],
        "dropout_fraction": 0.2,
        "seed": 20260911,
        "duplicate_probe": "SAME_PIXELS_SAME_OBSERVATION_DIFFERENT_EVIDENCE_ID",
        "social_absence": "REPLAY_INDEPENDENT_A1_NEVER_HIDE_COMBINED_A4_CITATIONS",
        "scenario_origin": "AUTHORED_TECHNICAL_PROBES_NOT_HUMAN_PREFERENCES",
        "scenarios": scenarios(),
        "human_evaluation": "EXCLUDED_BY_USER",
    }
    plan["plan_sha256"] = canonical_sha256(plan)
    write_once(directory / "evaluation/sensitivity-plan.json", plan)
    original, removed = [], []
    changes: Counter[str] = Counter()
    duplicate_checked = 0
    photo_ids = []
    for pid in ids:
        stem = pid.split(":")[-1]
        a = Assessment.model_validate_json(
            (directory / "final-assessments/photo-er" / (stem + ".json")).read_bytes()
        )
        text = Assessment.model_validate_json(
            (directory / "final-assessments/text" / (stem + ".json")).read_bytes()
        )
        verify_assessment(a)
        verify_assessment(text)
        photos = tuple(e for e in a.source.evidence if e.modality == "IMAGE")
        source = seal_bundle(
            a.source.place,
            tuple(e for e in a.source.evidence if e.modality != "IMAGE"),
            a.source.parent_source_sha256,
        )
        drop = build_assessment(
            source=source,
            judgments=a.judgments,
            rejections=a.rejections,
            policy=a.policy,
            model_request_sha256=a.model_request_sha256,
            assessed_at=a.assessed_at,
        )
        if values(drop) != values(text):
            raise ValueError("REMOVING_PHOTOS_DID_NOT_REPLAY_TEXT_VALUES")
        original.append(a)
        removed.append(drop)
        if not photos:
            continue
        photo_ids.append(pid)
        for key, old in values(a).items():
            new = values(drop)[key]
            if old == new:
                continue
            changes[
                "became_unknown"
                if new is None
                else "became_known"
                if old is None
                else "increased"
                if new > old
                else "decreased"
            ] += 1
        # Duplicate existing pixels with fresh evidence IDs; no extra credit.
        duplicated = tuple(
            seal_evidence(e.model_dump() | {"evidence_id": "duplicate-probe:" + e.record_sha256})
            for e in photos
        )
        probe = build_assessment(
            source=extend_source(a.source, duplicated),
            judgments=a.judgments,
            rejections=a.rejections,
            policy=a.policy,
            model_request_sha256=a.model_request_sha256,
            assessed_at=a.assessed_at,
        )
        if values(probe) != values(a) or probe.axes != a.axes:
            raise ValueError("EXACT_DUPLICATE_PHOTO_CHANGED_VALUES")
        duplicate_checked += len(photos)
    chosen = set(random.Random(plan["seed"]).sample(sorted(photo_ids), round(len(photo_ids) * 0.2)))
    random_missing = tuple(
        drop if a.source.place.place_id in chosen else a
        for a, drop in zip(original, removed, strict=True)
    )
    results = []
    for s in plan["scenarios"]:
        profile = build_intent(
            IntentSubmission(
                request_id=s["id"], answers={k: s["answers"].get(k, 0) for k in FACET_KEYS}
            ),
            created_at=EVALUATION_TIME,
        )
        before = rank(assessments=tuple(original), intent=profile, created_at=EVALUATION_TIME)
        after = rank(assessments=random_missing, intent=profile, created_at=EVALUATION_TIME)
        results.append(
            {
                "scenario": s["id"],
                "before_eligible": before["eligible_count"],
                "after_eligible": after["eligible_count"],
                "top5": overlap(before, after),
            }
        )
    report = {
        "version": plan["version"],
        "plan_sha256": plan["plan_sha256"],
        "photo_places": len(photo_ids),
        "duplicate_observations_checked": duplicate_checked,
        "duplicate_value_violations": 0,
        "all_photo_removal_facet_changes": dict(changes),
        "random_missing_place_ids": sorted(chosen),
        "scenarios": results,
        "interpretation": "기술적 민감도이며 사람의 추천 선호나 실제 만족도 변화가 아니다.",
    }
    report["report_sha256"] = canonical_sha256(report)
    atomic_json(directory / "evaluation/sensitivity.json", report)
    return report
