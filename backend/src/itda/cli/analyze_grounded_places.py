"""Production PUBLIC destination batch: official evidence → text assessment + visual mood.

Default membership is the entire currently pinned raw PUBLIC release. A selected
place is diagnostic only. This command never overwrites or activates old releases.
"""

from __future__ import annotations

import argparse
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from itda.catalog_paths import NATIONAL_CATALOG_PATH, NATIONAL_RELATIONS_PATH
from itda.contracts.destination_mood import DestinationMoodBundle, LightContext, Season
from itda.contracts.grounded_release import GroundedReleaseCandidate
from itda.contracts.grounded_source import (
    GroundedSourceRelease,
    build_source_release,
    parse_grounded_input_release,
)
from itda.contracts.mvp_daily_refresh import parse_daily_scored_release
from itda.contracts.mvp_public_catalog import PublicPlaceCatalog, PublicPlaceRelations
from itda.contracts.source_assessment import (
    AssessmentBundle,
    AssessmentReleaseManifest,
    PlaceMatch,
    SourceObservation,
    SourceReceipt,
)
from itda.domain.canonical import canonical_sha256
from itda.photo.model_control import ModelBatchControl, ModelBatchPaused
from itda.photo.provider.mood import MoodProvider
from itda.pipeline.destination_evidence import (
    DestinationEvidenceSnapshot,
    OfficialSourceCache,
    aliases_for,
    atomic_json,
    cache_lock,
    collect_destination,
    normalized,
    official_clients,
)
from itda.pipeline.destination_mood import (
    CachedDestinationMoodProvider,
    DestinationImageAsset,
    analyze_destination_mood,
)
from itda.pipeline.grounded_assessment import build_assessment
from itda.pipeline.grounded_place_scoring import (
    GroundedTextProvider,
    revalidate_stored_record,
    structured_facts,
)
from itda.pipeline.source_authority import SOURCE_AUTHORITY_VERSION


def _write_once(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with cache_lock(path):
        if path.exists():
            if json.loads(path.read_text()) != value:
                raise ValueError("immutable output already contains different data")
            return
        atomic_json(path, value)


def _keys(path: Path | None) -> dict[str, str]:
    result = dict(os.environ)
    if path:
        for line in path.read_text().splitlines():
            if line.lstrip().startswith("#") or "=" not in line:
                continue
            key, value = line.removeprefix("export ").split("=", 1)
            result.setdefault(key.strip(), value.strip().strip("\"'"))
    return result


def _assets(snapshot: DestinationEvidenceSnapshot) -> tuple[DestinationImageAsset, ...]:
    result = []
    for row in snapshot.images:
        if row.get("download_status") != "DOWNLOADED":
            continue
        month = row.get("capture_month")
        if (
            isinstance(month, str)
            and len(month) == 6
            and month.isdigit()
            and 1 <= int(month[4:]) <= 12
        ):
            month = month[:4] + "-" + month[4:]
        else:
            month = None
        season: Season = "UNKNOWN"
        if month:
            n = int(month[5:])
            season = (
                "SPRING"
                if n in {3, 4, 5}
                else "SUMMER"
                if n in {6, 7, 8}
                else "AUTUMN"
                if n in {9, 10, 11}
                else "WINTER"
            )
        metadata = row.get("metadata", {})
        keywords = str(metadata.get("galSearchKeyword", ""))
        # Official metadata explicitly saying night may stratify a photograph;
        # absence of a night keyword is not a daylight observation.
        light: LightContext = (
            "NIGHT" if any(word in keywords for word in ("야경", "야간", "밤풍경")) else "UNKNOWN"
        )
        result.append(
            DestinationImageAsset(
                asset_id=row["asset_id"],
                place_id=snapshot.place.place_id,
                path=Path(row["path"]),
                original_sha256=row["original_sha256"],
                receipt=SourceReceipt.model_validate(row["receipt"]),
                match=PlaceMatch.model_validate(row["match"]),
                license=row["license"],
                attribution_ko=row["attribution_ko"],
                capture_month=month,
                season=season,
                light_context=light,
            )
        )
    return tuple(result)


def run_batch(
    *,
    catalog: PublicPlaceCatalog,
    raw_release: Any,
    output: Path,
    cache: OfficialSourceCache,
    text_provider: GroundedTextProvider,
    mood_provider: MoodProvider | None,
    workers: int = 8,
    place_ids: tuple[str, ...] = (),
    live: bool = True,
    reuse_sources: Path | None = None,
    batch_control: ModelBatchControl | None = None,
) -> dict[str, Any]:
    if not 1 <= workers <= 40:
        raise ValueError("model workers must be1..40 within the shared session ceiling")
    raw_profiles = {p.place_id: p for p in raw_release.profiles}
    catalog_places = {p.place_id: p for p in catalog.places}
    if not set(raw_profiles) <= set(catalog_places):
        raise ValueError("raw release/catalog membership mismatch")
    selected = tuple(sorted(place_ids or tuple(raw_profiles)))
    if not set(selected) <= set(raw_profiles):
        raise ValueError("diagnostic place outside public release")
    if output.exists() and (output / "run.json").is_file():
        completed = json.loads((output / "run.json").read_text())
        # Resume validates existing immutable outputs below rather than returning
        # solely because a status file exists.
        if completed["raw_release_sha256"] != raw_release.release_sha256:
            raise ValueError("output raw release changed")
    name_counts: dict[str, int] = {}
    for p in catalog.places:
        for alias in {
            normalized(a)
            for a in aliases_for(
                p.name_ko, p.administrative_area if p.place_id.startswith("public:korea:") else None
            )
        }:
            name_counts[alias] = name_counts.get(alias, 0) + 1
    unique = {name for name, count in name_counts.items() if count == 1}
    snapshots = {}
    auth_failed = threading.Event()
    progress_lock = threading.Lock()

    def progress(payload):
        with progress_lock:
            print(json.dumps(payload, ensure_ascii=False), flush=True)

    def collect(pid):
        path = output / "sources" / (pid.rsplit(":", 1)[-1] + ".json")
        if path.is_file():
            snapshot = DestinationEvidenceSnapshot.model_validate_json(path.read_bytes())
            if snapshot.catalog_row_sha256 != catalog_places[pid].row_sha256:
                raise ValueError("source cache belongs to different catalog")
        elif reuse_sources is not None:
            snapshot = DestinationEvidenceSnapshot.model_validate_json(
                (reuse_sources / (pid.rsplit(":", 1)[-1] + ".json")).read_bytes()
            )
            if (
                snapshot.catalog_row_sha256 != catalog_places[pid].row_sha256
                or snapshot.place.place_id != pid
            ):
                raise ValueError("reused source catalog/place binding changed")
            _write_once(path, snapshot.model_dump(mode="json"))
        else:
            snapshot = collect_destination(
                catalog_places[pid],
                cache,
                image_directory=cache.root / "images",
                unique_names=unique,
                identity_version=text_provider.cache_version,
            )
            _write_once(path, snapshot.model_dump(mode="json"))
        if snapshot.coverage.get("semantic_evidence_version", "v1") != text_provider.cache_version:
            raise ValueError("source evidence identity and requested semantic cache version differ")
        progress(
            {
                "stage": "sources",
                "place_id": pid,
                "name": snapshot.place.name_ko,
                "coverage": snapshot.coverage,
            }
        )
        return pid, snapshot

    with ThreadPoolExecutor(max_workers=3) as executor:
        source_futures = [executor.submit(collect, pid) for pid in selected]
        try:
            for future in as_completed(source_futures):
                pid, snapshot = future.result()
                snapshots[pid] = snapshot
        except BaseException:
            for future in source_futures:
                future.cancel()
            raise
    source_hashes = tuple(
        sorted({canonical_sha256(s.model_dump(mode="json")) for s in snapshots.values()})
    )
    source_release = canonical_sha256(
        {
            "policy_version": "source-bundle-v1",
            "raw_release_sha256": raw_release.release_sha256,
            "source_snapshot_sha256": source_hashes,
        }
    )
    generated_at = datetime.now(UTC)
    run_context_path = output / "context.json"
    if run_context_path.is_file():
        context = json.loads(run_context_path.read_text())
        if context["source_release_sha256"] != source_release:
            raise ValueError("resumed static source identity changed")
        generated_at = datetime.fromisoformat(context["created_at"].replace("Z", "+00:00"))
    else:
        _write_once(
            run_context_path,
            {
                "source_release_sha256": source_release,
                "created_at": generated_at.isoformat().replace("+00:00", "Z"),
            },
        )
    outcomes = []

    def analyze(pid):
        if batch_control is not None:
            batch_control.check()
        stem = pid.rsplit(":", 1)[-1]
        snapshot = snapshots[pid]
        profile = raw_profiles[pid]
        assessment_path = output / "assessments" / (stem + ".json")
        audit_path = output / "audits" / (stem + ".json")
        mood_path = output / "moods" / (stem + ".json")
        if assessment_path.is_file() and audit_path.is_file():
            bundle = AssessmentBundle.model_validate_json(assessment_path.read_bytes())
            if (
                bundle.source_release_sha256 != source_release
                or bundle.raw_profile_sha256 != profile.profile_sha256
            ):
                raise ValueError("existing assessment binding mismatch")
            audit = json.loads(audit_path.read_text())
        else:
            attempts = []
            wire = None
            judgments = {}
            for attempt in (1, 2):
                if auth_failed.is_set():
                    raise PermissionError("MODEL_AUTH_CIRCUIT_OPEN")
                try:
                    wire, judgments, meta = text_provider.analyze(
                        snapshot,
                        cache_directory=cache.root / "models" / f"attempt-{attempt}",
                        live=live,
                    )
                    attempts.append(
                        {"attempt": attempt, "status": meta["validation_status"], **meta}
                    )
                    break
                except (ValueError, httpx.HTTPError) as error:
                    attempts.append(
                        {
                            "attempt": attempt,
                            "status": "UNAVAILABLE",
                            "error_type": type(error).__name__,
                            "http_status": getattr(error, "http_status", None),
                            "record_path": getattr(error, "record_path", None),
                            "validation_code": getattr(error, "validation_code", None),
                        }
                    )
                    if getattr(error, "http_status", None) in {401, 403}:
                        auth_failed.set()
                        raise PermissionError("MODEL_AUTHORIZATION_REJECTED") from None
                    if attempt == 1 and getattr(error, "http_status", None) in {
                        429,
                        500,
                        502,
                        503,
                        504,
                    }:
                        time.sleep(max(5, min(30, getattr(error, "retry_after", 0))))
            built = build_assessment(
                profile=profile,
                judgments=judgments,
                facts=structured_facts(snapshot),
                source_release_sha256=source_release,
                assessed_at=generated_at,
                independent_axes=wire.independent_axes if wire is not None else None,
            )
            bundle = built.bundle
            audit = {
                "schema_version": "grounded-assessment-audit.v1",
                "place_id": pid,
                "source_release_sha256": source_release,
                "assessment_bundle_sha256": bundle.bundle_sha256,
                "model_status": attempts[-1]["status"] if wire else "UNAVAILABLE",
                "attempts": attempts,
                "raw_axes": built.raw_axes,
                "axis_deltas": built.axis_deltas,
                "comparison_basis": built.comparison_basis,
                "supported_subordinate_counts": built.supported_subordinate_counts,
                "aggregation_policy_sha256": built.aggregation_policy_sha256,
            }
            _write_once(assessment_path, bundle.model_dump(mode="json"))
            _write_once(audit_path, audit)
        if mood_path.is_file():
            mood = DestinationMoodBundle.model_validate_json(mood_path.read_bytes())
            if (
                mood.source_release_sha256 != source_release
                or mood.raw_profile_sha256 != profile.profile_sha256
            ):
                raise ValueError("existing mood binding mismatch")
        else:
            mood = analyze_destination_mood(
                place_id=pid,
                raw_profile_sha256=profile.profile_sha256,
                source_release_sha256=source_release,
                assets=_assets(snapshot),
                provider=mood_provider,
                assessed_at=generated_at,
            )
            _write_once(mood_path, mood.model_dump(mode="json"))
        row = {
            "place_id": pid,
            "raw_profile_sha256": profile.profile_sha256,
            "assessment_bundle_sha256": bundle.bundle_sha256,
            "mood_bundle_sha256": mood.bundle_sha256,
            "model_status": audit["model_status"],
            "supported_subordinate_counts": audit["supported_subordinate_counts"],
            "analyzed_images": len(mood.images),
        }
        progress({"stage": "analysis", **row})
        return row

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(analyze, pid) for pid in selected]
        try:
            for future in as_completed(futures):
                outcomes.append(future.result())
        except ModelBatchPaused:
            for future in futures:
                future.cancel()
            raise
    outcomes.sort(key=lambda r: r["place_id"])
    members = [
        {k: r[k] for k in ("place_id", "raw_profile_sha256", "assessment_bundle_sha256")}
        for r in outcomes
    ]
    manifest = {
        "schema_version": "assessment-release.v1",
        "policy_version": "source-bundle-v1",
        "raw_release_sha256": raw_release.release_sha256,
        "source_snapshot_sha256": list(source_hashes),
        "source_release_sha256": source_release,
        "members": members,
        "assessment_set_sha256": canonical_sha256(
            {"source_release_sha256": source_release, "members": members}
        ),
        "created_at": generated_at.isoformat().replace("+00:00", "Z"),
    }
    manifest["manifest_sha256"] = canonical_sha256(manifest)
    _write_once(
        output / "manifest.json",
        AssessmentReleaseManifest.model_validate(manifest).model_dump(mode="json"),
    )
    report = {
        "schema_version": "grounded-destination-batch.v1",
        "scope": "PUBLIC_COMPLETE" if set(selected) == set(raw_profiles) else "DIAGNOSTIC_PARTIAL",
        "raw_release_sha256": raw_release.release_sha256,
        "source_release_sha256": source_release,
        "manifest_sha256": manifest["manifest_sha256"],
        "model": "glm-5.3-flash",
        "max_model_concurrency": workers,
        "reserved_online_model_slots": 40 - workers,
        "members": outcomes,
    }
    report["run_sha256"] = canonical_sha256(report)
    _write_once(output / "run.json", report)
    return report


def revalidate_existing_batch(
    source_directory: Path, output: Path, model_cache: Path
) -> dict[str, Any]:
    """Zero-network source-policy correction; preserve every prior immutable artifact."""
    old_manifest = AssessmentReleaseManifest.model_validate_json(
        (source_directory / "manifest.json").read_bytes()
    )
    old_candidate = json.loads((source_directory / "candidate.json").read_text())
    if old_candidate["candidate_sha256"] != canonical_sha256(
        {k: v for k, v in old_candidate.items() if k != "candidate_sha256"}
    ):
        raise ValueError("original candidate hash invalid")
    raw = parse_daily_scored_release(old_candidate["raw_release"])
    profiles = {p.place_id: p for p in raw.profiles}
    if raw.release_sha256 != old_manifest.raw_release_sha256:
        raise ValueError("original raw release differs")
    if tuple(profiles) != tuple(m.place_id for m in old_manifest.members):
        raise ValueError("original full membership differs")
    now = datetime.now(UTC)
    sources = []
    assessments = []
    moods = []
    rows = []
    changes = []
    for member in old_manifest.members:
        pid = member.place_id
        stem = pid.rsplit(":", 1)[-1]
        profile = profiles[pid]
        source = DestinationEvidenceSnapshot.model_validate_json(
            (source_directory / "sources" / (stem + ".json")).read_bytes()
        )
        previous = AssessmentBundle.model_validate_json(
            (source_directory / "assessments" / (stem + ".json")).read_bytes()
        )
        if (
            previous.bundle_sha256 != member.assessment_bundle_sha256
            or previous.raw_profile_sha256 != profile.profile_sha256
        ):
            raise ValueError("original assessment binding differs")
        previous_audit = json.loads((source_directory / "audits" / (stem + ".json")).read_text())
        record = next(
            (
                a
                for a in reversed(previous_audit["attempts"])
                if a.get("status") in {"VALIDATED", "PARTIAL"} and a.get("record_path")
            ),
            None,
        )
        wire = None
        judgments: dict[str, SourceObservation] = {}
        metadata = {
            "model_calls": 0,
            "validation_status": "UNAVAILABLE",
            "reason": "ORIGINAL_RESPONSE_UNAVAILABLE",
        }
        if record is not None:
            path = Path(record["record_path"])
            if not path.resolve().is_relative_to(model_cache.resolve()):
                raise ValueError("original model record outside approved cache")
            original_record = json.loads(path.read_text())
            if original_record["record_sha256"] != record["record_sha256"]:
                raise ValueError("original audit/model record digest differs")
            prior_judgments = original_record.get("validation", {}).get("normalized_judgments", {})
            if any(
                prior_judgments.get(k) != v.model_dump(mode="json")
                for k, v in previous.dimensions.items()
                if k not in "HER"
            ):
                raise ValueError("original cached judgments differ from original assessment")
            wire, judgments, metadata = revalidate_stored_record(
                source, path, output_directory=output / "revalidations"
            )
        built = build_assessment(
            profile=profile,
            judgments=judgments,
            facts=structured_facts(source),
            source_release_sha256=old_manifest.source_release_sha256,
            assessed_at=now,
            independent_axes=wire.independent_axes if wire else None,
        )
        mood = DestinationMoodBundle.model_validate_json(
            (source_directory / "moods" / (stem + ".json")).read_bytes()
        )
        changed = [
            k for k in previous.dimensions if previous.dimensions[k] != built.bundle.dimensions[k]
        ]
        if changed:
            changes.append(
                {
                    "place_id": pid,
                    "name": source.place.name_ko,
                    "dimensions": changed,
                    "before": {k: previous.dimensions[k].value for k in changed},
                    "after": {k: built.bundle.dimensions[k].value for k in changed},
                }
            )
        audit = {
            "schema_version": "grounded-assessment-audit.v1",
            "place_id": pid,
            "source_release_sha256": old_manifest.source_release_sha256,
            "assessment_bundle_sha256": built.bundle.bundle_sha256,
            "model_status": metadata["validation_status"],
            "attempts": [{"status": metadata["validation_status"], **metadata}],
            "raw_axes": built.raw_axes,
            "axis_deltas": built.axis_deltas,
            "comparison_basis": built.comparison_basis,
            "supported_subordinate_counts": built.supported_subordinate_counts,
            "aggregation_policy_sha256": built.aggregation_policy_sha256,
            "revalidation_of_candidate_sha256": old_candidate["candidate_sha256"],
            "source_authority_version": SOURCE_AUTHORITY_VERSION,
            "new_model_calls": 0,
        }
        for folder, value in [
            ("sources", source.model_dump(mode="json")),
            ("assessments", built.bundle.model_dump(mode="json")),
            ("moods", mood.model_dump(mode="json")),
            ("audits", audit),
        ]:
            _write_once(output / folder / (stem + ".json"), value)
        sources.append(source.model_dump(mode="json"))
        assessments.append(built.bundle)
        moods.append(mood)
        rows.append(
            {
                "place_id": pid,
                "raw_profile_sha256": profile.profile_sha256,
                "assessment_bundle_sha256": built.bundle.bundle_sha256,
                "mood_bundle_sha256": mood.bundle_sha256,
                "model_status": metadata["validation_status"],
                "supported_subordinate_counts": built.supported_subordinate_counts,
                "analyzed_images": len(mood.images),
            }
        )
    members = [
        {k: r[k] for k in ("place_id", "raw_profile_sha256", "assessment_bundle_sha256")}
        for r in rows
    ]
    manifest_fields = {
        "schema_version": "assessment-release.v1",
        "policy_version": "source-bundle-v1",
        "raw_release_sha256": raw.release_sha256,
        "source_snapshot_sha256": list(old_manifest.source_snapshot_sha256),
        "source_release_sha256": old_manifest.source_release_sha256,
        "members": members,
        "assessment_set_sha256": canonical_sha256(
            {"source_release_sha256": old_manifest.source_release_sha256, "members": members}
        ),
        "created_at": now.isoformat().replace("+00:00", "Z"),
    }
    manifest = AssessmentReleaseManifest.model_validate(
        manifest_fields | {"manifest_sha256": canonical_sha256(manifest_fields)}
    )
    run = {
        "schema_version": "grounded-destination-batch.v1",
        "scope": "PUBLIC_COMPLETE",
        "raw_release_sha256": raw.release_sha256,
        "source_release_sha256": old_manifest.source_release_sha256,
        "manifest_sha256": manifest.manifest_sha256,
        "model": "glm-5.3-flash",
        "source_authority_version": SOURCE_AUTHORITY_VERSION,
        "derivation": "UNCHANGED_RAW_RESPONSES_REVALIDATED",
        "new_model_calls": 0,
        "members": rows,
    }
    run["run_sha256"] = canonical_sha256(run)
    candidate_fields = {
        "schema_version": "grounded-release-candidate.v1",
        "raw_release": raw.model_dump(mode="json"),
        "manifest": manifest.model_dump(mode="json"),
        "assessments": [a.model_dump(mode="json") for a in assessments],
        "moods": [m.model_dump(mode="json") for m in moods],
        "source_snapshots": sources,
        "analysis_run": run,
        "created_at": now.isoformat().replace("+00:00", "Z"),
    }
    candidate = GroundedReleaseCandidate.model_validate(
        candidate_fields | {"candidate_sha256": canonical_sha256(candidate_fields)}
    )
    _write_once(output / "manifest.json", manifest.model_dump(mode="json"))
    _write_once(output / "run.json", run)
    _write_once(output / "candidate.json", candidate.model_dump(mode="json"))
    _write_once(
        output / "revalidation-summary.json",
        {
            "source_authority_version": SOURCE_AUTHORITY_VERSION,
            "candidate_sha256": candidate.candidate_sha256,
            "previous_candidate_sha256": old_candidate["candidate_sha256"],
            "new_model_calls": 0,
            "changed_places": changes,
            "m6_supported_before": sum(
                a["dimensions"]["M6"]["value"] is not None for a in old_candidate["assessments"]
            ),
            "m6_supported_after": sum(a.dimensions["M6"].value is not None for a in assessments),
        },
    )
    return {
        "candidate_sha256": candidate.candidate_sha256,
        "changed_places": len(changes),
        "new_model_calls": 0,
        "output": str(output),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--catalog",
        type=Path,
        default=NATIONAL_CATALOG_PATH,
    )
    parser.add_argument("--raw-release", type=Path)
    parser.add_argument(
        "--source-only",
        action="store_true",
        help="Analyze fresh catalog sources directly; do not import legacy scores",
    )
    parser.add_argument("--relations", type=Path, default=NATIONAL_RELATIONS_PATH)
    parser.add_argument("--provider-control-root", type=Path)
    parser.add_argument(
        "--resume-provider",
        action="store_true",
        help="Resume only after an external quota increase/reset has been confirmed",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cache", type=Path, default=Path("artifacts/national/source-cache"))
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--retry-model-limit", action="store_true")
    parser.add_argument("--retry-model-connection", action="store_true")
    parser.add_argument("--place-id", action="append", default=[])
    parser.add_argument("--source-ttl-hours", type=float, default=24)
    parser.add_argument("--refresh-sources", action="store_true")
    parser.add_argument(
        "--reuse-sources",
        type=Path,
        help="Verified immutable source directory from an earlier batch; no recollection",
    )
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--skip-mood", action="store_true")
    parser.add_argument("--semantic-cache-version", choices=("v1", "v2"), default="v2")
    parser.add_argument("--revalidate-from", type=Path)
    args = parser.parse_args(argv)
    # Fresh catalogs are the normal path. Historical scores require an explicit
    # input path; the retired MVP active pointer is never an implicit baseline.
    if args.raw_release is None and args.revalidate_from is None:
        args.source_only = True
    if args.source_only and (args.raw_release or args.revalidate_from or not args.relations):
        parser.error("source-only requires --relations and no historical raw/revalidation input")
    if args.revalidate_from:
        print(
            json.dumps(
                revalidate_existing_batch(args.revalidate_from, args.output, args.cache),
                ensure_ascii=False,
            )
        )
        return 0
    if args.refresh_sources and (args.reuse_sources or (args.output / "sources").exists()):
        parser.error("refresh requires a new output and no reused source snapshots")
    if args.source_ttl_hours < 0 or args.source_ttl_hours > 168:
        parser.error("source TTL must be0..168hours")
    for path in (args.catalog, args.raw_release):
        if path and any(
            "blind" in part.casefold() or part.casefold() == "sealed"
            for part in path.resolve().parts
        ):
            parser.error("blind/sealed inputs forbidden")
    keys = _keys(args.env_file)
    from itda.pipeline.national_public_catalog import (
        NationalProviderPaused,
        national_source_clients,
    )

    resources = ExitStack()
    if args.source_only:
        clients = resources.enter_context(
            national_source_clients(
                keys.get("TOUR_API_SERVICE_KEY", "offline-placeholder"),
                keys.get("ODII_SERVICE_KEY"),
                args.provider_control_root or args.cache.parent,
                resume_provider=args.resume_provider,
            )
        )
    else:
        clients = official_clients(
            keys.get("TOUR_API_SERVICE_KEY", "offline-placeholder"), keys.get("ODII_SERVICE_KEY")
        )
        for client in clients.values():
            resources.callback(client.close)
    cache = OfficialSourceCache(
        args.cache,
        clients=clients,
        live=not args.offline,
        ttl_days=0 if args.refresh_sources else args.source_ttl_hours / 24,
    )
    try:
        catalog = PublicPlaceCatalog.model_validate_json(args.catalog.read_bytes())
        if args.source_only:
            relations = PublicPlaceRelations.model_validate_json(args.relations.read_bytes())
            input_path = args.output / "source-release.json"
            if input_path.exists():
                release = GroundedSourceRelease.model_validate_json(input_path.read_bytes())
                expected = build_source_release(catalog, relations, created_at=release.created_at)
                if release != expected:
                    raise ValueError("resumed source-only catalog or relations changed")
            else:
                release = build_source_release(catalog, relations, created_at=datetime.now(UTC))
                _write_once(input_path, release.model_dump(mode="json"))
        else:
            release = parse_grounded_input_release(json.loads(args.raw_release.read_text()))
        key = keys.get("ZHIPUAI_API_KEY", "offline-placeholder")

        def record_model_retry(state):
            atomic_json(args.output / "model-retry.json", state)
            print(json.dumps({"stage": "model_retry", **state}), flush=True)

        batch_control = ModelBatchControl(
            retry_limits=args.retry_model_limit,
            retry_connections=args.retry_model_connection,
            on_retry=record_model_retry,
        )
        report = run_batch(
            catalog=catalog,
            raw_release=release,
            output=args.output,
            cache=cache,
            text_provider=GroundedTextProvider(
                api_key=key,
                cache_version=args.semantic_cache_version,
                batch_control=batch_control,
            ),
            mood_provider=None
            if args.skip_mood
            else CachedDestinationMoodProvider(
                api_key=key,
                cache_directory=cache.root / "mood-models",
                live=not args.offline,
                batch_control=batch_control,
            ),
            workers=args.workers,
            place_ids=tuple(args.place_id),
            live=not args.offline,
            reuse_sources=args.reuse_sources,
            batch_control=batch_control,
        )
        if report["scope"] == "PUBLIC_COMPLETE":
            from itda.db.assessment_release import load_candidate_from_directory

            candidate = load_candidate_from_directory(args.output, release)
            _write_once(args.output / "candidate.json", candidate.model_dump(mode="json"))
        print(
            json.dumps(
                {
                    "status": "complete",
                    "scope": report["scope"],
                    "members": len(report["members"]),
                    "output": str(args.output),
                },
                ensure_ascii=False,
            )
        )
    except ModelBatchPaused as error:
        atomic_json(args.output / "model-paused.json", error.state)
        print(json.dumps(error.state), flush=True)
        return 75
    except NationalProviderPaused as error:
        atomic_json(args.output / "source-paused.json", error.state)
        print(json.dumps({"status": "PAUSED", "reason": error.state.get("reason")}), flush=True)
        return 3
    finally:
        resources.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
