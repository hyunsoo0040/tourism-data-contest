"""Resumable source-only new-construct analysis with immutable run membership."""

from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from itda.authenticity.binding import bind_response
from itda.authenticity.contracts import Assessment, Evidence, Policy, SourceBundle
from itda.authenticity.model import GlmClient, ModelExchangeError, text_request
from itda.authenticity.rubric import RUBRIC_PAYLOAD, RUBRIC_SHA256
from itda.authenticity.scoring import build_assessment, verify_assessment
from itda.authenticity.sources import import_official_source
from itda.domain.canonical import canonical_sha256
from itda.photo.model_control import ModelBatchControl, ModelBatchPaused
from itda.pipeline.destination_evidence import atomic_json

COHORT_PATHS = {
    "initial": ("artifacts/national/20260909", "analysis"),
    "additional": ("artifacts/national/20260911-additional-1000", "analysis-recovery-20260911"),
}


def write_once(path: Path, payload: dict[str, Any]) -> None:
    if path.exists():
        if json.loads(path.read_text()) != payload:
            raise ValueError("IMMUTABLE_ANALYSIS_ARTIFACT_CHANGED")
    else:
        atomic_json(path, payload)


def store_versioned(path: Path, payload: dict[str, Any], *, hash_field: str) -> None:
    """Draft recovery can advance a pointer; every produced version remains immutable."""
    if path.exists():
        previous = json.loads(path.read_text())
        write_once(path.parent / "versions" / (previous[hash_field] + ".json"), previous)
    write_once(path.parent / "versions" / (payload[hash_field] + ".json"), payload)
    atomic_json(path, payload)


def prepare_diagnostic(repository: Path, directory: Path) -> dict[str, Any]:
    audit_path = repository / "artifacts/evaluation/national-quality-20260911/quality-data.json"
    audit = json.loads(audit_path.read_text())
    catalogs = {
        key: json.loads((repository / root / "catalog.json").read_text())
        for key, (root, _) in COHORT_PATHS.items()
    }
    places = {p["place_id"]: p for cat in catalogs.values() for p in cat["places"]}
    members = []
    for row in sorted(audit["cases"], key=lambda c: c["id"]):
        cohort: Literal["initial", "additional"] = (
            "initial" if row["cohort"] == "initial" else "additional"
        )
        root, analysis = COHORT_PATHS[cohort]
        original = repository / root / analysis / "sources" / (row["id"].split(":")[-1] + ".json")
        source = import_official_source(
            original, duplicate_group_id=places[row["id"]]["duplicate_group_id"], cohort=cohort
        )
        file = directory / "sources" / (row["id"].split(":")[-1] + ".json")
        write_once(file, source.model_dump(mode="json"))
        members.append(
            {
                "place_id": row["id"],
                "name_ko": row["name"],
                "cohort": cohort,
                "case_kind": row["kind"],
                "source_file": str(file.resolve()),
                "source_bundle_sha256": source.bundle_sha256,
                "parent_file": str(original),
                "parent_file_sha256": hashlib.sha256(original.read_bytes()).hexdigest(),
            }
        )
    payload = {
        "schema_version": "authenticity-analysis-manifest.v1",
        "scope": "DIAGNOSTIC_DEVELOPMENT",
        "rubric_sha256": RUBRIC_SHA256,
        "selection_source_sha256": hashlib.sha256(audit_path.read_bytes()).hexdigest(),
        "members": members,
        "human_evaluation": "EXCLUDED_BY_USER",
        "model_concurrency_limit": 5,
    }
    payload["manifest_sha256"] = canonical_sha256(payload)
    write_once(directory / "manifest.json", payload)
    write_once(directory / "rubric.json", RUBRIC_PAYLOAD)
    return payload


def run_text_batch(
    *,
    manifest_path: Path,
    directory: Path,
    api_key: str,
    workers: int = 5,
    live: bool = False,
) -> dict[str, Any]:
    if type(workers) is not int or not 1 <= workers <= 5:
        raise ValueError("USER_MODEL_CONCURRENCY_LIMIT_IS_FIVE")
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("manifest_sha256") != canonical_sha256(
        {k: v for k, v in manifest.items() if k != "manifest_sha256"}
    ):
        raise ValueError("ANALYSIS_MANIFEST_DIGEST_MISMATCH")
    if manifest.get("rubric_sha256") != RUBRIC_SHA256:
        raise ValueError("MANIFEST_RUBRIC_CHANGED")
    if len({m["place_id"] for m in manifest["members"]}) != len(manifest["members"]):
        raise ValueError("DUPLICATED_ANALYSIS_MEMBER")
    control = ModelBatchControl(
        retry_limits=True,
        retry_connections=True,
        on_retry=lambda state: atomic_json(directory / "model-state.json", state),
    )
    client = GlmClient(api_key=api_key, control=control)
    started = datetime.now(UTC)

    def analyze(member: dict[str, Any]) -> dict[str, Any]:
        control.check()
        source = SourceBundle.model_validate_json(Path(member["source_file"]).read_bytes())
        if (
            source.bundle_sha256 != member["source_bundle_sha256"]
            or source.place.place_id != member["place_id"]
        ):
            raise ValueError("MANIFEST_SOURCE_CHANGED")
        stem = source.place.place_id.split(":")[-1]
        output = directory / "assessments" / (stem + ".json")
        audit_path = directory / "audits" / (stem + ".json")
        if output.exists():
            assessment = Assessment.model_validate_json(output.read_bytes())
            verify_assessment(assessment)
            prior = json.loads(audit_path.read_text())
            if (
                prior["input_source_sha256"] != source.bundle_sha256
                or prior["assessment_sha256"] != assessment.assessment_sha256
            ):
                raise ValueError("RESUMED_ASSESSMENT_SOURCE_MISMATCH")
            return dict(prior) | {"resumed": True}
        payload, bound = text_request(source)
        attempts: list[dict[str, Any]] = []
        for attempt in (1, 2):
            try:
                wire, meta = client.complete(
                    payload, directory=directory / "model-cache" / f"attempt-{attempt}", live=live
                )
                judgments, rejections = bind_response(wire, bound)
                assessment = build_assessment(
                    source=bound,
                    judgments=judgments,
                    rejections=rejections,
                    policy=Policy(),
                    model_request_sha256=meta["request_sha256"],
                    assessed_at=datetime.now(UTC),
                )
                verify_assessment(assessment)
                write_once(output, assessment.model_dump(mode="json"))
                result = {
                    "place_id": source.place.place_id,
                    "name_ko": source.place.name_ko,
                    "status": "PARTIAL" if rejections else "VALIDATED",
                    "input_source_sha256": source.bundle_sha256,
                    "bound_source_sha256": bound.bundle_sha256,
                    "assessment_sha256": assessment.assessment_sha256,
                    "model": meta,
                    "rejected_facets": [r.model_dump(mode="json") for r in rejections],
                    "attempts": attempts,
                    "resumed": False,
                }
                write_once(audit_path, result)
                return result
            except ModelBatchPaused:
                raise
            except ModelExchangeError as error:
                attempts.append(
                    {
                        "attempt": attempt,
                        "code": error.code,
                        "http_status": error.http_status,
                        "record": error.record_path,
                    }
                )
                if error.http_status in {401, 403}:
                    raise
            except ValueError as error:
                attempts.append({"attempt": attempt, "code": str(error)[:200]})
        result = {
            "place_id": source.place.place_id,
            "name_ko": source.place.name_ko,
            "status": "UNAVAILABLE",
            "input_source_sha256": source.bundle_sha256,
            "attempts": attempts,
            "resumed": False,
        }
        atomic_json(audit_path, result)
        return result

    rows = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(analyze, member) for member in manifest["members"]]
        try:
            for future in as_completed(futures):
                row = future.result()
                rows.append(row)
                print(
                    json.dumps(
                        {
                            "stage": "AUTHENTICITY_TEXT",
                            "place": row["name_ko"],
                            "status": row["status"],
                            "completed": len(rows),
                            "total": len(futures),
                        },
                        ensure_ascii=False,
                    ),
                    flush=True,
                )
                atomic_json(
                    directory / "progress.json",
                    {
                        "stage": "TEXT_ANALYSIS",
                        "completed": len(rows),
                        "total": len(futures),
                        "updated_at": datetime.now(UTC).isoformat(),
                    },
                )
        except (ModelBatchPaused, ModelExchangeError):
            for future in futures:
                future.cancel()
            raise
    summary = {
        "schema_version": "authenticity-text-batch.v1",
        "manifest_sha256": manifest["manifest_sha256"],
        "rubric_sha256": RUBRIC_SHA256,
        "started_at": started.isoformat(),
        "completed_at": datetime.now(UTC).isoformat(),
        "requested_places": len(manifest["members"]),
        "completed_records": len(rows),
        "statuses": {
            s: sum(r["status"] == s for r in rows) for s in ("VALIDATED", "PARTIAL", "UNAVAILABLE")
        },
        "human_evaluation": "EXCLUDED_BY_USER",
        "semantic_accuracy": "NOT_ESTABLISHED",
        "model_concurrency": workers,
        "rows": sorted(rows, key=lambda r: r["place_id"]),
    }
    summary["report_sha256"] = canonical_sha256(summary)
    atomic_json(directory / "summary.json", summary)
    return summary


def run_photo_batch(
    *,
    manifest_path: Path,
    directory: Path,
    repository: Path,
    api_key: str,
    workers: int = 5,
    live: bool = False,
) -> dict[str, Any]:
    from itda.authenticity.appearance import APPEARANCE_PROMPT_SHA256, analyze_asset
    from itda.authenticity.photo_recovery import PhotoExcluded, PhotoRecoveryClient
    from itda.authenticity.sources import extend_source
    from itda.contracts.destination_mood import DestinationMoodBundle

    if type(workers) is not int or not 1 <= workers <= 5:
        raise ValueError("USER_MODEL_CONCURRENCY_LIMIT_IS_FIVE")
    manifest = json.loads(manifest_path.read_text())
    if manifest["manifest_sha256"] != canonical_sha256(
        {k: v for k, v in manifest.items() if k != "manifest_sha256"}
    ):
        raise ValueError("MANIFEST_DIGEST_MISMATCH")
    control = ModelBatchControl(
        retry_limits=True,
        retry_connections=True,
        on_retry=lambda state: atomic_json(directory / "appearance/model-state.json", state),
    )
    client = PhotoRecoveryClient(api_key=api_key, control=control)

    def analyze(member: dict[str, Any]) -> dict[str, Any]:
        control.check()
        stem = member["place_id"].split(":")[-1]
        original_path = Path(member["parent_file"])
        if hashlib.sha256(original_path.read_bytes()).hexdigest() != member["parent_file_sha256"]:
            raise ValueError("ORIGINAL_PHOTO_SOURCE_CHANGED")
        original = json.loads(original_path.read_text())
        old_mood_path = original_path.parent.parent / "moods" / (stem + ".json")
        mood = DestinationMoodBundle.model_validate_json(old_mood_path.read_bytes())
        if mood.place_id != member["place_id"]:
            raise ValueError("PHOTO_SELECTION_PLACE_MISMATCH")
        assets = {a["asset_id"]: a for a in original["images"]}
        records: list[Evidence] = []
        decisions = []
        for image in mood.images:
            raw_asset = assets[image.asset_id]
            if raw_asset["original_sha256"] != image.original_sha256:
                raise ValueError("SELECTED_PHOTO_HASH_CHANGED")
            try:
                observations, packet = analyze_asset(
                    raw_asset=raw_asset,
                    repository=repository,
                    directory=directory / "appearance",
                    client=client,
                    place_id=member["place_id"],
                    live=live,
                )
                records.extend(observations)
                decisions.append(
                    {"asset_id": image.asset_id, "status": "OBSERVED", "packet": packet}
                )
            except PhotoExcluded as error:
                decisions.append(
                    {
                        "asset_id": image.asset_id,
                        "status": "EXCLUDED",
                        "reason": str(error),
                        "exclusion": error.decision,
                    }
                )
            except ModelBatchPaused:
                raise
            except (ModelExchangeError, ValueError) as error:
                decisions.append(
                    {
                        "asset_id": image.asset_id,
                        "status": "UNAVAILABLE",
                        "reason": str(error)[:300],
                    }
                )
        assessment_path = directory / "assessments" / (stem + ".json")
        if assessment_path.exists():
            text = Assessment.model_validate_json(assessment_path.read_bytes())
            verify_assessment(text)
            enriched = extend_source(text.source, tuple(records))
            for mode, folder in (
                ("ER", "photo-assessments"),
                ("HER_CONDITIONAL", "photo-conditional-assessments"),
            ):
                fused = build_assessment(
                    source=enriched,
                    judgments=text.judgments,
                    rejections=text.rejections,
                    policy=Policy.model_validate({"photo_mode": mode}),
                    model_request_sha256=text.model_request_sha256,
                    assessed_at=text.assessed_at,
                )
                verify_assessment(fused)
                store_versioned(
                    directory / folder / (stem + ".json"),
                    fused.model_dump(mode="json"),
                    hash_field="assessment_sha256",
                )
        result = {
            "place_id": member["place_id"],
            "name_ko": member["name_ko"],
            "selected_images": len(mood.images),
            "observed_images": sum(d["status"] == "OBSERVED" for d in decisions),
            "excluded_images": sum(d["status"] == "EXCLUDED" for d in decisions),
            "decisions": decisions,
            "human_evaluation": "EXCLUDED_BY_USER",
            "review_kind": "MODEL_APPEARANCE_OBSERVATION_NOT_GROUND_TRUTH",
        }
        audit_path = directory / "appearance/audits" / (stem + ".json")
        if audit_path.exists():
            old = json.loads(audit_path.read_text())
            write_once(audit_path.parent / "history" / (canonical_sha256(old) + ".json"), old)
        atomic_json(audit_path, result)
        return result

    rows = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(analyze, m) for m in manifest["members"]]
        try:
            for future in as_completed(futures):
                row = future.result()
                rows.append(row)
                print(
                    json.dumps(
                        {
                            "stage": "AUTHENTICITY_APPEARANCE",
                            "place": row["name_ko"],
                            "images": row["observed_images"],
                            "completed": len(rows),
                            "total": len(futures),
                        },
                        ensure_ascii=False,
                    ),
                    flush=True,
                )
        except ModelBatchPaused:
            for future in futures:
                future.cancel()
            raise
    report = {
        "schema_version": "authenticity-appearance-batch.v1",
        "manifest_sha256": manifest["manifest_sha256"],
        "appearance_prompt_sha256": APPEARANCE_PROMPT_SHA256,
        "places": len(rows),
        "selected_images": sum(r["selected_images"] for r in rows),
        "observed_images": sum(r["observed_images"] for r in rows),
        "excluded_images": sum(r["excluded_images"] for r in rows),
        "completed_at": datetime.now(UTC).isoformat(),
        "model_concurrency": workers,
        "human_evaluation": "EXCLUDED_BY_USER",
        "rows": sorted(rows, key=lambda r: r["place_id"]),
    }
    report["report_sha256"] = canonical_sha256(report)
    store_versioned(directory / "appearance/summary.json", report, hash_field="report_sha256")
    return report


def run_review_batch(
    *,
    manifest_path: Path,
    directory: Path,
    api_key: str,
    workers: int = 5,
    live: bool = False,
) -> dict[str, Any]:
    from itda.authenticity.review import repair_assessment, review_assessment
    from itda.authenticity.sources import extend_source

    if type(workers) is not int or not 1 <= workers <= 5:
        raise ValueError("USER_MODEL_CONCURRENCY_LIMIT_IS_FIVE")
    manifest = json.loads(manifest_path.read_text())
    if manifest["manifest_sha256"] != canonical_sha256(
        {k: v for k, v in manifest.items() if k != "manifest_sha256"}
    ):
        raise ValueError("MANIFEST_DIGEST_MISMATCH")
    control = ModelBatchControl(
        retry_limits=True,
        retry_connections=True,
        on_retry=lambda state: atomic_json(directory / "semantic-review/model-state.json", state),
    )
    client = GlmClient(api_key=api_key, control=control)

    def analyze(member: dict[str, Any]) -> dict[str, Any]:
        control.check()
        stem = member["place_id"].split(":")[-1]
        base_path = directory / "assessments" / (stem + ".json")
        if not base_path.exists():
            return {"place_id": member["place_id"], "status": "TEXT_UNAVAILABLE"}
        original = Assessment.model_validate_json(base_path.read_bytes())
        verify_assessment(original)
        audit = json.loads((directory / "audits" / (stem + ".json")).read_text())
        wire: object
        if audit.get("wire_recovery_path"):
            from itda.authenticity.wire_recovery import load as load_recovered_wire

            wire = load_recovered_wire(
                Path(audit["wire_recovery_path"]), audit["model"]["request_sha256"]
            )
        else:
            record_path = Path(audit["model"]["record_path"])
            record = json.loads(record_path.read_text())
            wire, _ = client.complete(record["request"], directory=record_path.parent, live=False)
        repaired, repair_report = repair_assessment(
            original, original_wire=wire, client=client, directory=directory / "repair", live=live
        )
        store_versioned(
            directory / "repaired-assessments" / (stem + ".json"),
            repaired.model_dump(mode="json"),
            hash_field="assessment_sha256",
        )
        reviewed, review_report = review_assessment(
            repaired, client=client, directory=directory / "semantic-review", live=live
        )
        store_versioned(
            directory / "final-assessments/text" / (stem + ".json"),
            reviewed.model_dump(mode="json"),
            hash_field="assessment_sha256",
        )
        photo_path = directory / "photo-assessments" / (stem + ".json")
        if photo_path.exists():
            photo = Assessment.model_validate_json(photo_path.read_bytes())
            verify_assessment(photo)
            enriched = extend_source(
                reviewed.source, tuple(e for e in photo.source.evidence if e.modality == "IMAGE")
            )
            for mode, folder in (("ER", "photo-er"), ("HER_CONDITIONAL", "photo-her")):
                fused = build_assessment(
                    source=enriched,
                    judgments=reviewed.judgments,
                    rejections=reviewed.rejections,
                    policy=Policy.model_validate({"photo_mode": mode}),
                    model_request_sha256=reviewed.model_request_sha256,
                    assessed_at=reviewed.assessed_at,
                )
                store_versioned(
                    directory / "final-assessments" / folder / (stem + ".json"),
                    fused.model_dump(mode="json"),
                    hash_field="assessment_sha256",
                )
        result = {
            "place_id": member["place_id"],
            "name_ko": member["name_ko"],
            "status": "AI_REVIEWED",
            "original_assessment_sha256": original.assessment_sha256,
            "repaired_assessment_sha256": repaired.assessment_sha256,
            "final_text_assessment_sha256": reviewed.assessment_sha256,
            "repair": repair_report,
            "semantic_review": review_report,
            "scope": "AI_ASSISTED_NOT_HUMAN_GROUND_TRUTH",
        }
        atomic_json(directory / "semantic-review/audits" / (stem + ".json"), result)
        return result

    rows = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(analyze, m) for m in manifest["members"]]
        try:
            for future in as_completed(futures):
                row = future.result()
                rows.append(row)
                print(
                    json.dumps(
                        {
                            "stage": "AUTHENTICITY_SEMANTIC_REVIEW",
                            "place": row.get("name_ko", row["place_id"]),
                            "status": row["status"],
                            "completed": len(rows),
                            "total": len(futures),
                        },
                        ensure_ascii=False,
                    ),
                    flush=True,
                )
        except (ModelBatchPaused, ModelExchangeError):
            for future in futures:
                future.cancel()
            raise
    report = {
        "schema_version": "authenticity-ai-review-batch.v1",
        "manifest_sha256": manifest["manifest_sha256"],
        "places": len(rows),
        "completed_at": datetime.now(UTC).isoformat(),
        "human_evaluation": "EXCLUDED_BY_USER",
        "scope": "AUTOMATIC_AND_AI_ASSISTED_ONLY",
        "rows": sorted(rows, key=lambda r: r["place_id"]),
    }
    report["report_sha256"] = canonical_sha256(report)
    atomic_json(directory / "semantic-review/summary.json", report)
    return report


def prepare_development(repository: Path, directory: Path) -> dict[str, Any]:
    """120 distinct exposed development places; not relabeled blind data."""
    import random
    import shutil

    root = repository / "artifacts/authenticity-v1/20260911"
    audit = json.loads(
        (
            repository / "artifacts/evaluation/national-quality-20260911/quality-data.json"
        ).read_text()
    )
    pilot = json.loads((root / "instagram-pilot/pilot-manifest.json").read_text())
    seed_ids = {p["place_id"] for p in pilot["places"]}
    rng = random.Random(20260912)
    chosen = []
    for cohort_group in ("initial", "additional"):
        pool = [r for r in audit["places"] if r["cohort"] == cohort_group]
        selected = sorted((r for r in pool if r["id"] in seed_ids), key=lambda r: r["id"])
        used = {r["id"] for r in selected}
        remaining = sorted((r for r in pool if r["id"] not in used), key=lambda r: r["id"])
        rng.shuffle(remaining)
        # Ensure enough distinct photo places for the declared visual benchmark.
        for row in remaining:
            if sum(r["photos"] > 0 for r in selected) >= 30:
                break
            if row["photos"] > 0:
                selected.append(row)
                used.add(row["id"])
        groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for row in remaining:
            if row["id"] not in used:
                groups.setdefault((row["category"], row["region"].split()[0]), []).append(row)
        keys = sorted(groups)
        rng.shuffle(keys)
        while len(selected) < 60:
            for key in keys:
                if groups[key] and len(selected) < 60:
                    selected.append(groups[key].pop())
        chosen.extend(selected)
    members = []
    catalogs = {
        c: {
            p["place_id"]: p
            for p in json.loads((repository / r / "catalog.json").read_text())["places"]
        }
        for c, (r, _) in COHORT_PATHS.items()
    }
    for row in sorted(chosen, key=lambda r: r["id"]):
        cohort: Literal["initial", "additional"] = (
            "initial" if row["cohort"] == "initial" else "additional"
        )
        r, a = COHORT_PATHS[cohort]
        parent = repository / r / a / "sources" / (row["id"].split(":")[-1] + ".json")
        source = import_official_source(
            parent,
            duplicate_group_id=catalogs[cohort][row["id"]]["duplicate_group_id"],
            cohort=cohort,
        )
        file = directory / "sources" / (row["id"].split(":")[-1] + ".json")
        write_once(file, source.model_dump(mode="json"))
        members.append(
            {
                "place_id": row["id"],
                "name_ko": row["name"],
                "cohort": cohort,
                "source_file": str(file.resolve()),
                "source_bundle_sha256": source.bundle_sha256,
                "parent_file": str(parent),
                "parent_file_sha256": hashlib.sha256(parent.read_bytes()).hexdigest(),
            }
        )
    manifest = {
        "schema_version": "authenticity-analysis-manifest.v1",
        "scope": "EXPOSED_DEVELOPMENT",
        "rubric_sha256": RUBRIC_SHA256,
        "members": members,
        "human_evaluation": "EXCLUDED_BY_USER",
        "selection": "PILOT40_PLUS_SEEDED_REGION_CATEGORY_PHOTO_COVERAGE",
        "seed": 20260912,
        "model_concurrency_limit": 5,
        "blind": False,
    }
    manifest["manifest_sha256"] = canonical_sha256(manifest)
    write_once(directory / "manifest.json", manifest)
    write_once(directory / "rubric.json", RUBRIC_PAYLOAD)
    # Reuse exact verified requests. Never regenerate already successful diagnostic calls.
    for relative in (
        "model-cache",
        "appearance/model-cache",
        "repair/model-cache",
        "semantic-review/model-cache",
    ):
        old = root / "diagnostic" / relative
        if old.exists():
            for file in old.rglob("*.json"):
                target = directory / relative / file.relative_to(old)
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists() and target.read_bytes() != file.read_bytes():
                    raise ValueError("EXISTING_MODEL_CACHE_DIFFERS")
                if not target.exists():
                    shutil.copy2(file, target)
    return manifest
