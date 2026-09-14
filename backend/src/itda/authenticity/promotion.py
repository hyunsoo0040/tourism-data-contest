"""Require the completed, source-traced full recipe before public packaging."""

from __future__ import annotations

import json
from pathlib import Path

from itda.authenticity.contracts import Assessment, Policy
from itda.authenticity.photo_recovery import photo_stage_complete
from itda.authenticity.report import checked
from itda.authenticity.scoring import verify_assessment


def verify_public_recipe(directory: Path, assessments: tuple[Assessment, ...]) -> None:
    manifest = checked(directory / "manifest.json", "manifest_sha256")
    if (
        manifest.get("scope") != "VERSIONED_FULL_CORPUS_REANALYSIS"
        or len(manifest["members"]) != 2000
    ):
        raise ValueError("PUBLIC_REQUIRES_FROZEN_FULL_2000_MEMBERSHIP")
    terminal = directory / "workflow-photo-review.json"
    if not terminal.exists():
        raise ValueError("PUBLIC_REQUIRES_COMPLETE_PIXEL_REVIEW_WORKFLOW")
    state = json.loads(terminal.read_text())
    if state.get("status") != "COMPLETE" or state.get("exit_code") != 0:
        raise ValueError("PUBLIC_REQUIRES_COMPLETE_PIXEL_REVIEW_WORKFLOW")
    if not photo_stage_complete(checked(directory / "appearance/summary.json")):
        raise ValueError("PUBLIC_REQUIRES_ACCOUNTED_PHOTO_RESULTS")
    recipe = checked(directory / "recipe.json", "recipe_sha256")
    heldout = checked(directory.parent / "new-evaluation/evaluation/results.json")
    if heldout["recipe_sha256"] != recipe["recipe_sha256"] or any(
        c["hard_violations"] or c["places"] != 60 for c in heldout["conditions"].values()
    ):
        raise ValueError("PUBLIC_NEW_PLACE_RECIPE_GATE_FAILED")
    pixels = checked(directory / "photo-review/summary.json")
    fusion = checked(directory / "photo-review/fusion.json")
    if fusion["photo_review_sha256"] != pixels["report_sha256"] or fusion["places"] != 2000:
        raise ValueError("PUBLIC_PIXEL_REVIEW_FUSION_MISMATCH")
    accepted = {r["materialization_sha256"]: set(r["approved_keys"]) for r in pixels["rows"]}
    expected = Policy.model_validate(recipe["policy"])
    if {a.source.place.place_id for a in assessments} != {
        m["place_id"] for m in manifest["members"]
    } or len(assessments) != 2000:
        raise ValueError("PUBLIC_FULL_CORPUS_ASSESSMENTS_INCOMPLETE")
    for assessment in assessments:
        verify_assessment(assessment)
        if assessment.policy != expected or assessment.source.place.cohort not in {
            "initial",
            "additional",
        }:
            raise ValueError("PUBLIC_SCORING_POLICY_OR_COHORT_CHANGED")
        stem = assessment.source.place.place_id.split(":")[-1] + ".json"
        text = Assessment.model_validate_json(
            (directory / "final-assessments/text" / stem).read_bytes()
        )
        original = Assessment.model_validate_json(
            (directory / "photo-assessments" / stem).read_bytes()
        )
        verify_assessment(text)
        verify_assessment(original)
        if assessment.judgments != text.judgments:
            raise ValueError("PUBLIC_TEXT_JUDGMENTS_CHANGED")
        evidence = {e.evidence_id: e for e in text.source.evidence}
        for e in original.source.evidence:
            if (
                e.modality == "IMAGE"
                and e.appearance
                and e.appearance.key in accepted[e.receipt.source_record_sha256]
            ):
                evidence[e.evidence_id] = e
        if {e.evidence_id: e for e in assessment.source.evidence} != evidence:
            raise ValueError("PUBLIC_PHOTO_EVIDENCE_DIFFERS_FROM_AI_FILTER")
