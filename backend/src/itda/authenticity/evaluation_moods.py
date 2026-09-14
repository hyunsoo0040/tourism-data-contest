"""Observe already downloaded evaluation pixels; never resume official collection."""

from __future__ import annotations

import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any

from itda.authenticity.batch import store_versioned, write_once
from itda.cli.analyze_grounded_places import _assets
from itda.contracts.destination_mood import DestinationMoodBundle
from itda.contracts.grounded_source import build_source_release
from itda.contracts.mvp_public_catalog import PublicPlaceCatalog, PublicPlaceRelations
from itda.domain.canonical import canonical_sha256
from itda.photo.model_control import ModelBatchControl
from itda.pipeline.destination_evidence import DestinationEvidenceSnapshot, atomic_json
from itda.pipeline.destination_mood import CachedDestinationMoodProvider, analyze_destination_mood


def run(
    *, directory: Path, collection: Path, api_key: str, workers: int = 5, live: bool = False
) -> dict[str, Any]:
    if type(workers) is not int or not 1 <= workers <= 5:
        raise ValueError("USER_MODEL_CONCURRENCY_LIMIT_IS_FIVE")
    os.environ["ITDA_MODEL_SESSION_LIMIT"] = "5"
    manifest = json.loads((directory / "manifest.json").read_text())
    if manifest["manifest_sha256"] != canonical_sha256(
        {k: v for k, v in manifest.items() if k != "manifest_sha256"}
    ):
        raise ValueError("NEW_EVALUATION_MANIFEST_CHANGED")
    recipe = json.loads((directory / "recipe.json").read_text())
    catalog = PublicPlaceCatalog.model_validate_json((collection / "catalog.json").read_bytes())
    relations = PublicPlaceRelations.model_validate_json(
        (collection / "relations.json").read_bytes()
    )
    release = build_source_release(
        catalog, relations, created_at=datetime.fromisoformat(recipe["frozen_at"])
    )
    write_once(directory / "source-profile-release.json", release.model_dump(mode="json"))
    profiles = {p.place_id: p for p in release.profiles}
    if set(profiles) != {m["place_id"] for m in manifest["members"]}:
        raise ValueError("NEW_EVALUATION_MOOD_MEMBERSHIP_CHANGED")
    control = ModelBatchControl(
        retry_limits=True,
        retry_connections=True,
        on_retry=lambda state: atomic_json(directory / "mood/model-state.json", state),
    )
    provider = CachedDestinationMoodProvider(
        api_key=api_key,
        cache_directory=directory / "mood/model-cache",
        live=live,
        batch_control=control,
    )

    def analyze(member: dict[str, Any]) -> dict[str, Any]:
        control.check()
        parent = Path(member["parent_file"])
        if hashlib.sha256(parent.read_bytes()).hexdigest() != member["parent_file_sha256"]:
            raise ValueError("NEW_EVALUATION_PIXEL_SOURCE_CHANGED")
        source = DestinationEvidenceSnapshot.model_validate_json(parent.read_bytes())
        path = parent.parent.parent / "moods" / parent.name
        if path.exists():
            mood = DestinationMoodBundle.model_validate_json(path.read_bytes())
            if (
                mood.raw_profile_sha256 != profiles[member["place_id"]].profile_sha256
                or mood.source_release_sha256 != release.release_sha256
            ):
                raise ValueError("NEW_EVALUATION_MOOD_SOURCE_CHANGED")
        else:
            mood = analyze_destination_mood(
                place_id=member["place_id"],
                raw_profile_sha256=profiles[member["place_id"]].profile_sha256,
                source_release_sha256=release.release_sha256,
                assets=_assets(source),
                provider=provider,
                assessed_at=release.created_at,
            )
            store_versioned(path, mood.model_dump(mode="json"), hash_field="bundle_sha256")
        return {
            "place_id": member["place_id"],
            "images": len(mood.images),
            "bundle_sha256": mood.bundle_sha256,
            "decisions": [d.model_dump(mode="json") for d in mood.decisions],
        }

    rows = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(analyze, m) for m in manifest["members"]]
        try:
            for future in as_completed(futures):
                rows.append(future.result())
                print(
                    json.dumps(
                        {"stage": "EVALUATION_MOOD", "completed": len(rows), "total": len(futures)}
                    ),
                    flush=True,
                )
        except Exception:
            for future in futures:
                future.cancel()
            raise
    report = {
        "version": "authenticity-new-evaluation-moods-v1",
        "manifest_sha256": manifest["manifest_sha256"],
        "places": len(rows),
        "observed_images": sum(r["images"] for r in rows),
        "official_api_calls": 0,
        "human_evaluation": "EXCLUDED_BY_USER",
        "rows": sorted(rows, key=lambda r: r["place_id"]),
    }
    report["report_sha256"] = canonical_sha256(report)
    atomic_json(directory / "mood/summary.json", report)
    return report
