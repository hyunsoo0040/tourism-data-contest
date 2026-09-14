"""Reproducible 40-place diagnostic pilot; tag links are candidates until inspected."""

from __future__ import annotations

import json
import random
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from itda.domain.canonical import canonical_sha256
from itda.pipeline.destination_evidence import atomic_json

PILOT_SEED = 20260911


def _tag(value: str) -> str:
    return re.sub(r"[^\w]", "", value, flags=re.UNICODE).strip("_")


def prepare_pilot(*, repository: Path, output: Path) -> dict[str, Any]:
    audit_path = repository / "artifacts/evaluation/national-quality-20260911/quality-data.json"
    audit = json.loads(audit_path.read_text())
    rows = audit["places"]
    cases = {c["id"] for c in audit["cases"]}
    selected = []
    rng = random.Random(PILOT_SEED)
    for cohort in ("initial", "additional"):
        pool = [r for r in rows if r["cohort"] == cohort]
        chosen = sorted((r for r in pool if r["id"] in cases), key=lambda r: r["id"])
        used = {r["id"] for r in chosen}
        strata: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for row in sorted(pool, key=lambda r: r["id"]):
            if row["id"] not in used:
                strata[(row["category"], row["region"].split()[0])].append(row)
        for group in strata.values():
            rng.shuffle(group)
        keys = sorted(strata)
        rng.shuffle(keys)
        while len(chosen) < 20:
            for key in keys:
                if strata[key] and len(chosen) < 20:
                    chosen.append(strata[key].pop())
            if not any(strata.values()) and len(chosen) < 20:
                raise ValueError("INSUFFICIENT_PILOT_PLACES")
        selected.extend(chosen)
    prepared = []
    all_tags: dict[str, list[str]] = defaultdict(list)
    for row in selected:
        root = (
            "artifacts/national/20260909/analysis"
            if row["cohort"] == "initial"
            else "artifacts/national/20260911-additional-1000/analysis-recovery-20260911"
        )
        snapshot = json.loads(
            (repository / root / "sources" / (row["id"].split(":")[-1] + ".json")).read_text()
        )
        place = snapshot["place"]
        plain = re.sub(r"\([^)]*\)|\[[^]]*\]", "", row["name"]).strip()
        city = row["region"].split()[-1]
        names = [plain, row["name"], *place["aliases"], city + plain]
        tags = []
        for name in names:
            candidate = _tag(name)
            if candidate and candidate not in tags and len(candidate) <= 100:
                tags.append(candidate)
            if len(tags) == 3:
                break
        if not tags:
            raise ValueError("NO_DERIVED_TAG")
        for tag in tags:
            all_tags[tag].append(row["id"])
        prepared.append(
            {
                "place_id": row["id"],
                "name_ko": row["name"],
                "cohort": row["cohort"],
                "region": row["region"],
                "category": row["category"],
                "primary_tag": tags[0],
                "candidate_tags": tags,
                "mapping_state": "CANDIDATE_NOT_VERIFIED",
                "selection_reason": "PRIOR_DIAGNOSTIC_CASE"
                if row["id"] in cases
                else "SEEDED_REGION_CATEGORY_STRATUM",
                "source_snapshot_sha256": snapshot["snapshot_sha256"],
            }
        )
    payload = {
        "schema_version": "instagram-pilot-manifest.v1",
        "seed": PILOT_SEED,
        "place_count": len(prepared),
        "tag_count": len(all_tags),
        "max_places": 40,
        "max_tags": 120,
        "budget_usd": "10.00",
        "places": prepared,
        "tags": sorted(all_tags),
        "ambiguous_shared_tags": {k: v for k, v in all_tags.items() if len(v) > 1},
        "selection": "PURPOSEFUL_DIAGNOSTIC_NOT_PREVALENCE_SAMPLE",
        "tag_rule": "OFFICIAL_NAME_AND_ALIASES_THEN_CITY_PREFIX;PRIMARY_SELECTED_BEFORE_COUNTS",
        "human_evaluation": "EXCLUDED_BY_USER",
    }
    payload["manifest_sha256"] = canonical_sha256(payload)
    target = output / "pilot-manifest.json"
    if target.exists() and json.loads(target.read_text()) != payload:
        raise ValueError("PILOT_MANIFEST_CHANGED_DURING_RESUME")
    atomic_json(target, payload)
    return payload
