"""One recorded protocol-recovery attempt after two invalid JSON responses."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from itda.authenticity.batch import store_versioned, write_once
from itda.authenticity.binding import bind_response
from itda.authenticity.contracts import Policy, SourceBundle
from itda.authenticity.model import GlmClient, ModelExchangeError, text_request
from itda.authenticity.scoring import build_assessment, verify_assessment
from itda.authenticity.wire_recovery import from_attempts
from itda.domain.canonical import canonical_sha256
from itda.pipeline.destination_evidence import atomic_json, cache_lock


def eligible(audit: dict[str, Any]) -> bool:
    attempts = audit.get("attempts", [])
    return (
        audit.get("status") == "UNAVAILABLE"
        and len(attempts) == 2
        and all(a.get("code") == "MODEL_JSON_RESPONSE_REJECTED" for a in attempts)
    )


def recover(directory: Path, *, api_key: str, live: bool = False) -> dict[str, Any]:
    with cache_lock(directory / "format-recovery/run"):
        return _recover(directory, api_key=api_key, live=live)


def _recover(directory: Path, *, api_key: str, live: bool) -> dict[str, Any]:
    manifest = json.loads((directory / "manifest.json").read_text())
    if manifest["manifest_sha256"] != canonical_sha256(
        {k: v for k, v in manifest.items() if k != "manifest_sha256"}
    ):
        raise ValueError("RECOVERY_MANIFEST_CHANGED")
    plan = {
        "version": "authenticity-format-recovery-v1",
        "manifest_sha256": manifest["manifest_sha256"],
        "eligibility": "TWO_JSON_RESPONSE_FAILURES_ONLY",
        "additional_attempts_per_request": 1,
        "first_step": "LOSSLESS_LEADING_COMPLETE_JSON_WITH_SUFFIX_AUDIT_NO_VALUE_CHANGES",
        "request_policy": "IDENTICAL_FROZEN_REQUEST_NO_SCORE_OR_PROMPT_CHANGES",
    }
    plan["plan_sha256"] = canonical_sha256(plan)
    write_once(directory / "format-recovery/plan.json", plan)
    client = GlmClient(api_key=api_key)
    results = []
    for member in manifest["members"]:
        stem = member["place_id"].split(":")[-1] + ".json"
        path = directory / "audits" / stem
        if not path.exists():
            continue
        previous = json.loads(path.read_text())
        if previous.get("status") != "UNAVAILABLE":
            continue
        if not eligible(previous):
            results.append(
                {
                    "place_id": member["place_id"],
                    "status": "UNAVAILABLE",
                    "code": "NOT_ELIGIBLE_FOR_JSON_FORMAT_RECOVERY",
                }
            )
            continue
        source = SourceBundle.model_validate_json(Path(member["source_file"]).read_bytes())
        if (
            source.bundle_sha256 != member["source_bundle_sha256"]
            or source.bundle_sha256 != previous["input_source_sha256"]
        ):
            raise ValueError("RECOVERY_SOURCE_CHANGED")
        payload, bound = text_request(source)
        digest = canonical_sha256(payload)
        cache = directory / "model-cache/format-recovery"
        result = {"place_id": member["place_id"], "request_sha256": digest, "status": "UNAVAILABLE"}
        try:
            recovered_wire = from_attempts(directory, digest)
            wire_path = None
            wire: object
            try:
                if recovered_wire:
                    wire, meta, wire_path = recovered_wire
                else:
                    wire, meta = client.complete(payload, directory=cache, live=False)
            except ModelExchangeError as error:
                if error.code != "OFFLINE_MODEL_CACHE_MISS" or not live:
                    raise
                reservation = directory / "format-recovery/reservations" / (digest + ".json")
                if reservation.exists() or list(cache.glob(digest + "-*.attempt.json")):
                    raise ModelExchangeError("FORMAT_RECOVERY_ATTEMPT_LIMIT_REACHED") from None
                write_once(
                    reservation,
                    {
                        "request_sha256": digest,
                        "maximum_additional_dispatches": 1,
                        "reserved_at": datetime.now(UTC).isoformat(),
                        "purpose": "UNCERTAIN_DISPATCH_MUST_NOT_BE_AUTOMATICALLY_REPEATED",
                    },
                )
                wire, meta = client.complete(payload, directory=cache, live=True)
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
            write_once(directory / "assessments" / stem, assessment.model_dump(mode="json"))
            write_once(
                directory / "audits/history" / (canonical_sha256(previous) + ".json"), previous
            )
            audit = {
                "place_id": member["place_id"],
                "name_ko": member["name_ko"],
                "status": "PARTIAL" if rejections or wire_path else "VALIDATED",
                "input_source_sha256": source.bundle_sha256,
                "bound_source_sha256": bound.bundle_sha256,
                "assessment_sha256": assessment.assessment_sha256,
                "model": meta,
                "rejected_facets": [r.model_dump(mode="json") for r in rejections],
                "attempts": previous["attempts"],
                "resumed": False,
                "format_recovery_plan_sha256": plan["plan_sha256"],
            }
            if wire_path:
                audit["wire_recovery_path"] = str(wire_path)
                audit["protocol_warning"] = "ORIGINAL_RESPONSE_HAD_UNSTRUCTURED_SUFFIX"
            atomic_json(path, audit)
            result.update(status=audit["status"], assessment_sha256=assessment.assessment_sha256)
        except (ModelExchangeError, ValueError) as error:
            result["code"] = (
                error.code if isinstance(error, ModelExchangeError) else str(error)[:200]
            )
            if isinstance(error, ModelExchangeError) and error.http_status in {401, 403}:
                raise
        atomic_json(directory / "format-recovery/audits" / stem, result)
        results.append(result)
        print(json.dumps(result), flush=True)
    report = {
        "plan_sha256": plan["plan_sha256"],
        "recovered": sum(r["status"] != "UNAVAILABLE" for r in results),
        "still_unavailable": sum(r["status"] == "UNAVAILABLE" for r in results),
        "rows": results,
    }
    report["report_sha256"] = canonical_sha256(report)
    store_versioned(directory / "format-recovery/summary.json", report, hash_field="report_sha256")
    return report
