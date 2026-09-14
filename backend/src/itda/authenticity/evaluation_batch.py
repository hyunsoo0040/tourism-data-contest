"""Collect new evaluation source snapshots only after the development recipe freeze."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from itda.authenticity.batch import write_once
from itda.authenticity.rubric import RUBRIC_PAYLOAD, RUBRIC_SHA256
from itda.authenticity.sources import import_official_source
from itda.contracts.mvp_public_catalog import PublicPlaceCatalog
from itda.domain.canonical import canonical_sha256
from itda.pipeline.destination_evidence import (
    DestinationEvidenceSnapshot,
    OfficialSourceCache,
    aliases_for,
    collect_destination,
    normalized,
    official_clients,
)
from itda.pipeline.national_public_catalog import national_source_clients


def prepare(
    *,
    repository: Path,
    directory: Path,
    collection: Path,
    keys: dict[str, str],
    offline: bool = False,
) -> dict[str, Any]:
    recipe = json.loads(
        (
            repository / "artifacts/authenticity-v1/20260911/development/evaluation/recipe.json"
        ).read_text()
    )
    if recipe["recipe_sha256"] != canonical_sha256(
        {k: v for k, v in recipe.items() if k != "recipe_sha256"}
    ):
        raise ValueError("EVALUATION_RECIPE_CHANGED")
    for relative, digest in recipe["pipeline_code_sha256"].items():
        if hashlib.sha256((repository / relative).read_bytes()).hexdigest() != digest:
            raise ValueError("FROZEN_RECIPE_CODE_CHANGED_BEFORE_NEW_PLACE_EVALUATION")
    catalog = PublicPlaceCatalog.model_validate_json((collection / "catalog.json").read_bytes())
    completion = json.loads((collection / "completion-report.json").read_text())
    if completion["report_sha256"] != canonical_sha256(
        {k: v for k, v in completion.items() if k != "report_sha256"}
    ):
        raise ValueError("NEW_PLACE_COLLECTION_REPORT_CHANGED")
    if any(
        completion[k] != 0 for k in ("overlapping_ids", "overlapping_name_coordinate_identities")
    ):
        raise ValueError("NEW_PLACE_EVALUATION_OVERLAP")
    for filename, digest in completion["files"].items():
        if hashlib.sha256((collection / filename).read_bytes()).hexdigest() != digest:
            raise ValueError("NEW_PLACE_COLLECTION_ARTIFACT_CHANGED")
    # Alias uniqueness spans both old corpora and the new sample, rather than
    # treating a name as nationally unique because its namesake is outside 60.
    names: Counter[str] = Counter()
    pools = [catalog]
    for parent in ("20260909", "20260911-additional-1000"):
        pools.append(
            PublicPlaceCatalog.model_validate_json(
                (repository / "artifacts/national" / parent / "catalog.json").read_bytes()
            )
        )
    for catalog_pool in pools:
        for p in catalog_pool.places:
            names.update({normalized(a) for a in aliases_for(p.name_ko, p.administrative_area)})
    unique = {name for name, count in names.items() if count == 1}
    with ExitStack() as resources:
        if offline:
            clients = official_clients("offline-placeholder", None)
            for client in clients.values():
                resources.callback(client.close)
        else:
            clients = resources.enter_context(
                national_source_clients(
                    keys["TOUR_API_SERVICE_KEY"], keys.get("ODII_SERVICE_KEY"), collection
                )
            )
        cache = OfficialSourceCache(
            collection / "official-cache", clients=clients, live=not offline, ttl_days=3650
        )

        def collect(place: Any) -> dict[str, Any]:
            path = collection / "source-snapshots" / (place.place_id.split(":")[-1] + ".json")
            if path.exists():
                snapshot = DestinationEvidenceSnapshot.model_validate_json(path.read_bytes())
                if (
                    snapshot.catalog_row_sha256 != place.row_sha256
                    or snapshot.place.place_id != place.place_id
                ):
                    raise ValueError("NEW_EVALUATION_SNAPSHOT_CHANGED")
            else:
                snapshot = collect_destination(
                    place,
                    cache,
                    image_directory=cache.root / "images",
                    unique_names=unique,
                    identity_version="v2",
                )
                write_once(path, snapshot.model_dump(mode="json"))
            source = import_official_source(
                path, duplicate_group_id=place.duplicate_group_id, cohort="new-evaluation"
            )
            output = directory / "sources" / path.name
            write_once(output, source.model_dump(mode="json"))
            return {
                "place_id": place.place_id,
                "name_ko": place.name_ko,
                "cohort": "new-evaluation",
                "source_file": str(output.resolve()),
                "source_bundle_sha256": source.bundle_sha256,
                "parent_file": str(path),
                "parent_file_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }

        members = []
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = [pool.submit(collect, p) for p in catalog.places]
            try:
                for future in as_completed(futures):
                    members.append(future.result())
                    print(
                        json.dumps(
                            {
                                "stage": "NEW_EVALUATION_SOURCES",
                                "completed": len(members),
                                "total": len(catalog.places),
                            }
                        ),
                        flush=True,
                    )
            except Exception:
                for future in futures:
                    future.cancel()
                raise
    manifest = {
        "schema_version": "authenticity-analysis-manifest.v1",
        "scope": "NEW_PLACE_AUTOMATIC_EVALUATION",
        "rubric_sha256": RUBRIC_SHA256,
        "recipe_sha256": recipe["recipe_sha256"],
        "collection_report_sha256": completion["report_sha256"],
        "members": sorted(members, key=lambda m: m["place_id"]),
        "human_evaluation": "EXCLUDED_BY_USER",
        "model_concurrency_limit": 5,
        "source_collection_mode": "EXISTING_CACHE_ONLY_AFTER_PROVIDER_QUOTA" if offline else "LIVE",
        "social_collection": "NOT_AUTHORIZED_FOR_NEW_SAMPLE",
    }
    manifest["manifest_sha256"] = canonical_sha256(manifest)
    write_once(directory / "manifest.json", manifest)
    write_once(directory / "rubric.json", RUBRIC_PAYLOAD)
    write_once(directory / "recipe.json", recipe)
    return manifest
