"""Freeze the existing 2,000-place corpus for a separate versioned reanalysis."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any, Literal

from itda.authenticity.batch import COHORT_PATHS, write_once
from itda.authenticity.rubric import RUBRIC_PAYLOAD, RUBRIC_SHA256
from itda.authenticity.sources import import_official_source
from itda.domain.canonical import canonical_sha256


def prepare(repository: Path, directory: Path) -> dict[str, Any]:
    development = repository / "artifacts/authenticity-v1/20260911/development"
    recipe = json.loads((development / "evaluation/recipe.json").read_text())
    if (
        recipe["recipe_sha256"]
        != canonical_sha256({k: v for k, v in recipe.items() if k != "recipe_sha256"})
        or recipe["rubric_sha256"] != RUBRIC_SHA256
    ):
        raise ValueError("FULL_ANALYSIS_RECIPE_CHANGED")
    members = []
    for cohort in ("initial", "additional"):
        typed: Literal["initial", "additional"] = "initial" if cohort == "initial" else "additional"
        root, analysis = COHORT_PATHS[cohort]
        catalog = json.loads((repository / root / "catalog.json").read_text())
        for place in catalog["places"]:
            parent = (
                repository
                / root
                / analysis
                / "sources"
                / (place["place_id"].split(":")[-1] + ".json")
            )
            source = import_official_source(
                parent, duplicate_group_id=place["duplicate_group_id"], cohort=typed
            )
            target = directory / "sources" / parent.name
            write_once(target, source.model_dump(mode="json"))
            members.append(
                {
                    "place_id": source.place.place_id,
                    "name_ko": source.place.name_ko,
                    "cohort": cohort,
                    "source_file": str(target.resolve()),
                    "source_bundle_sha256": source.bundle_sha256,
                    "parent_file": str(parent),
                    "parent_file_sha256": hashlib.sha256(parent.read_bytes()).hexdigest(),
                }
            )
    if len(members) != 2000 or len({m["place_id"] for m in members}) != 2000:
        raise ValueError("FULL_ANALYSIS_REQUIRES_FROZEN_2000_DISTINCT_PLACES")
    manifest = {
        "schema_version": "authenticity-analysis-manifest.v1",
        "scope": "VERSIONED_FULL_CORPUS_REANALYSIS",
        "rubric_sha256": RUBRIC_SHA256,
        "recipe_sha256": recipe["recipe_sha256"],
        "members": sorted(members, key=lambda m: m["place_id"]),
        "blind": False,
        "human_evaluation": "EXCLUDED_BY_USER",
        "model_concurrency_limit": 5,
        "social_collection": "NO_PAID_EXPANSION",
    }
    manifest["manifest_sha256"] = canonical_sha256(manifest)
    write_once(directory / "manifest.json", manifest)
    write_once(directory / "rubric.json", RUBRIC_PAYLOAD)
    write_once(directory / "recipe.json", recipe)
    for relative in (
        "model-cache",
        "appearance/model-cache",
        "repair/model-cache",
        "semantic-review/model-cache",
        "photo-review/model-cache",
    ):
        old = development / relative
        for file in old.rglob("*.json"):
            target = directory / relative / file.relative_to(old)
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() and target.read_bytes() != file.read_bytes():
                raise ValueError("FULL_MODEL_CACHE_CONFLICT")
            if not target.exists():
                shutil.copy2(file, target)
    return manifest
