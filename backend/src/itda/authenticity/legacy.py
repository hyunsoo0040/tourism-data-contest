"""Replay frozen legacy arithmetic without reinterpreting it as the new construct."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from itda.authenticity.batch import COHORT_PATHS, store_versioned
from itda.contracts.source_assessment import AssessmentBundle
from itda.domain.canonical import canonical_sha256
from itda.pipeline.grounded_assessment import AGGREGATION_POLICY_SHA256, aggregate_axis


def replay(repository: Path, output: Path) -> dict[str, Any]:
    rows = []
    for cohort, (base, analysis) in COHORT_PATHS.items():
        directory = repository / base / analysis
        catalog = json.loads((repository / base / "catalog.json").read_text())
        expected = {p["place_id"] for p in catalog["places"]}
        actual = set()
        for path in sorted((directory / "assessments").glob("*.json")):
            bundle = AssessmentBundle.model_validate_json(path.read_bytes())
            actual.add(bundle.place_id)
            axes = {}
            for axis in "HER":
                recomputed = aggregate_axis(axis, bundle.dimensions)
                prior = bundle.dimensions[axis]
                if (recomputed.value, recomputed.state) != (prior.value, prior.state):
                    raise ValueError("LEGACY_AXIS_ARITHMETIC_REPLAY_DIFFERS")
                if {e.evidence_id for e in recomputed.evidence} != {
                    e.evidence_id for e in prior.evidence
                }:
                    raise ValueError("LEGACY_AXIS_EVIDENCE_UNION_DIFFERS")
                axes[axis] = prior.value
            rows.append(
                {
                    "place_id": bundle.place_id,
                    "cohort": cohort,
                    "axes": axes,
                    "bundle_sha256": bundle.bundle_sha256,
                    "file": str(path),
                    "file_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
        if expected != actual:
            raise ValueError("LEGACY_REPLAY_MEMBERSHIP_DIFFERS")
    report = {
        "version": "authenticity-legacy-arithmetic-replay-v1",
        "places": len(rows),
        "axes_checked": 3 * len(rows),
        "arithmetic_mismatches": 0,
        "evidence_union_mismatches": 0,
        "aggregation_policy_sha256": AGGREGATION_POLICY_SHA256,
        "aggregation_code_sha256": hashlib.sha256(
            Path(aggregate_axis.__code__.co_filename).read_bytes()
        ).hexdigest(),
        "interpretation": "FROZEN_LEGACY_ARITHMETIC_ONLY_NOT_NEW_CONSTRUCT_OR_SEMANTIC_ACCURACY",
        "rows": rows,
    }
    report["report_sha256"] = canonical_sha256(report)
    store_versioned(output, report, hash_field="report_sha256")
    return report
