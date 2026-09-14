"""Bounded recovery of frozen failed photo requests, with auditable exclusions."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from itda.authenticity.appearance import APPEARANCE_KEYS, normalize_appearance
from itda.authenticity.batch import write_once
from itda.authenticity.contracts import Appearance
from itda.authenticity.model import MODEL, GlmClient, ModelExchangeError
from itda.domain.canonical import canonical_sha256
from itda.pipeline.destination_evidence import cache_lock


class PhotoExcluded(ValueError):
    def __init__(self, decision: dict[str, Any]) -> None:
        self.decision = decision
        super().__init__(decision["reason"])


def checked(path: Path, field: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text())
    if data[field] != canonical_sha256({k: v for k, v in data.items() if k != field}):
        raise ValueError("PHOTO_RECOVERY_ARTIFACT_CHANGED")
    return data


def read_record(path: Path, request_sha: str) -> dict[str, Any]:
    record = checked(path, "record_sha256")
    if (
        record["request_sha256"] != request_sha
        or canonical_sha256(record["request"]) != request_sha
        or hashlib.sha256(record["raw_response"].encode()).hexdigest() != record["response_sha256"]
    ):
        raise ValueError("PHOTO_RECOVERY_REQUEST_OR_RESPONSE_CHANGED")
    return record


def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("PHOTO_RECOVERY_DUPLICATED_KEY")
        result[key] = value
    return result


def extract(record: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Extract exactly one finished JSON object; never evaluate model code."""
    envelope = json.loads(record["raw_response"])
    if (
        record["http_status"] != 200
        or envelope.get("model") != MODEL
        or len(envelope.get("choices", [])) != 1
    ):
        raise ValueError("PHOTO_RECOVERY_RESPONSE_IDENTITY_INVALID")
    choice = envelope["choices"][0]
    if choice.get("finish_reason") != "stop" or choice.get("message", {}).get("tool_calls"):
        raise ValueError("PHOTO_RECOVERY_RESPONSE_INCOMPLETE")
    content = choice["message"]["content"]
    if not isinstance(content, str) or not content.lstrip().startswith("{"):
        raise ValueError("PHOTO_RECOVERY_NO_LEADING_JSON")
    leading = content.lstrip()
    raw, end = json.JSONDecoder(object_pairs_hook=unique).raw_decode(leading)
    suffix = leading[end:]
    if any(c in suffix for c in "{}[]"):
        raise ValueError("PHOTO_RECOVERY_AMBIGUOUS_SUFFIX")
    if not isinstance(raw, dict) or set(raw) != {"scene_status", "observations"}:
        raise ValueError("PHOTO_RECOVERY_ENVELOPE_INVALID")
    metadata = {
        "json_char_start": len(content) - len(leading),
        "json_char_end": len(content) - len(leading) + end,
        "json_text_sha256": hashlib.sha256(leading[:end].encode()).hexdigest(),
        "suffix_sha256": hashlib.sha256(suffix.encode()).hexdigest(),
        "suffix_characters": len(suffix),
        "values_rewritten": False,
    }
    return raw, metadata


def scene_excluded(raw: dict[str, Any]) -> bool:
    if raw.get("scene_status") != "NOT_EVALUABLE":
        return False
    rows = raw.get("observations")
    if not isinstance(rows, list) or len(rows) != 3:
        return False
    parsed = [Appearance.model_validate(row) for row in rows]
    return {p.key for p in parsed} == set(APPEARANCE_KEYS)


def save_decision(
    root: Path, plan: dict[str, Any], path: Path, record: dict[str, Any], *, reason: str
) -> dict[str, Any]:
    value = {
        "version": "authenticity-photo-recovery-decision.v1",
        "plan_sha256": plan["plan_sha256"],
        "plan_path": str(root / "plan.json"),
        "request_sha256": record["request_sha256"],
        "record_path": str(path),
        "record_sha256": record["record_sha256"],
        "reason": reason,
        "contributes_evidence": False,
    }
    value["decision_sha256"] = canonical_sha256(value)
    write_once(root / "decisions" / (value["decision_sha256"] + ".json"), value)
    return value


class PhotoRecoveryClient(GlmClient):
    def complete(
        self, payload: dict[str, Any], *, directory: Path, live: bool = False
    ) -> tuple[object, dict[str, Any]]:
        root = directory.parent.parent / "photo-recovery"
        if not (root / "plan.json").exists():
            return super().complete(payload, directory=directory, live=live)
        plan = checked(root / "plan.json", "plan_sha256")
        digest = canonical_sha256(payload)
        if digest not in plan["request_sha256s"]:
            # Frozen successful requests must reuse their original cache.
            return super().complete(payload, directory=directory, live=False)
        with cache_lock(root / "locks" / digest):
            return self._recover(payload, directory, root, plan, digest, live)

    def _recover(
        self,
        payload: dict[str, Any],
        directory: Path,
        root: Path,
        plan: dict[str, Any],
        digest: str,
        live: bool,
    ) -> tuple[object, dict[str, Any]]:
        extra = root / "model-cache"
        for folder in (directory, extra):
            attempts = [
                (read_record(path, digest), path)
                for path in folder.glob(digest + "-*.attempt.json")
            ]
            for record, path in sorted(attempts, key=lambda pair: pair[0]["retrieved_at"]):
                if record["http_status"] in {401, 403}:
                    raise ModelExchangeError("MODEL_HTTP_ERROR", status=record["http_status"])
                try:
                    raw, extraction = extract(record)
                    if scene_excluded(raw):
                        raise PhotoExcluded(
                            save_decision(root, plan, path, record, reason="NOT_EVALUABLE_SCENE")
                        )
                    normalize_appearance(raw)
                except PhotoExcluded:
                    raise
                except (ValueError, KeyError, TypeError):
                    continue
                recovered = {
                    "version": "authenticity-photo-lossless-recovery.v1",
                    "plan_sha256": plan["plan_sha256"],
                    "request_sha256": digest,
                    "record_path": str(path),
                    "record_sha256": record["record_sha256"],
                    "wire": raw,
                    "extraction": extraction,
                    "used_additional_response": folder == extra,
                }
                recovered["recovery_sha256"] = canonical_sha256(recovered)
                saved = root / "wires" / (recovered["recovery_sha256"] + ".json")
                write_once(saved, recovered)
                return raw, {
                    "request_sha256": digest,
                    "record_path": str(path),
                    "record_sha256": record["record_sha256"],
                    "response_sha256": record["response_sha256"],
                    "retrieved_at": record["retrieved_at"],
                    "cached": True,
                    "photo_recovery_path": str(saved),
                }
        reservation = root / "reservations" / (digest + ".json")
        if reservation.exists():
            # A known invalid completed response may be excluded; an uncertain
            # dispatch or transport failure remains unavailable and stops work.
            extra_paths = sorted(extra.glob(digest + "-*.attempt.json"))
            if len(extra_paths) == 1:
                record = read_record(extra_paths[0], digest)
                if record["http_status"] == 200:
                    raise PhotoExcluded(
                        save_decision(
                            root,
                            plan,
                            extra_paths[0],
                            record,
                            reason="INVALID_RESPONSE_AFTER_ONE_ADDITIONAL_ATTEMPT",
                        )
                    )
            raise ModelExchangeError("PHOTO_RECOVERY_DISPATCH_UNCERTAIN_NO_REPEAT")
        if not live:
            raise ModelExchangeError("OFFLINE_PHOTO_RECOVERY_NEEDS_ONE_ATTEMPT")
        write_once(
            reservation,
            {
                "request_sha256": digest,
                "maximum_additional_dispatches": 1,
                "reserved_at": datetime.now(UTC).isoformat(),
                "plan_sha256": plan["plan_sha256"],
            },
        )
        try:
            super().complete(payload, directory=extra, live=True)
        except ModelExchangeError as error:
            if error.code != "MODEL_JSON_RESPONSE_REJECTED":
                raise
        return self._recover(payload, directory, root, plan, digest, False)


def verify_exclusion(decision: dict[str, Any]) -> None:
    if (
        decision["decision_sha256"]
        != canonical_sha256({k: v for k, v in decision.items() if k != "decision_sha256"})
        or decision["contributes_evidence"] is not False
    ):
        raise ValueError("PHOTO_EXCLUSION_CHANGED")
    plan = checked(Path(decision["plan_path"]), "plan_sha256")
    digest = decision["request_sha256"]
    if plan["plan_sha256"] != decision["plan_sha256"] or digest not in plan["request_sha256s"]:
        raise ValueError("PHOTO_EXCLUSION_PLAN_MISMATCH")
    record = read_record(Path(decision["record_path"]), digest)
    if record["record_sha256"] != decision["record_sha256"]:
        raise ValueError("PHOTO_EXCLUSION_RECORD_MISMATCH")
    if decision["reason"] == "NOT_EVALUABLE_SCENE":
        raw, _ = extract(record)
        if not scene_excluded(raw):
            raise ValueError("PHOTO_EXCLUSION_SCENE_CHANGED")
    elif decision["reason"] == "INVALID_RESPONSE_AFTER_ONE_ADDITIONAL_ATTEMPT":
        root = Path(decision["plan_path"]).parent
        reservation = json.loads((root / "reservations" / (digest + ".json")).read_text())
        if (
            reservation["plan_sha256"] != plan["plan_sha256"]
            or reservation["request_sha256"] != digest
            or reservation["maximum_additional_dispatches"] != 1
            or Path(decision["record_path"]).parent != root / "model-cache"
            or record["http_status"] != 200
        ):
            raise ValueError("PHOTO_EXCLUSION_ATTEMPT_MISMATCH")
        try:
            raw, _ = extract(record)
            normalize_appearance(raw)
        except (ValueError, KeyError, TypeError):
            return
        raise ValueError("VALID_PHOTO_RESPONSE_CANNOT_BE_EXCLUDED_AS_INVALID")
    else:
        raise ValueError("PHOTO_EXCLUSION_REASON_UNKNOWN")


def photo_stage_complete(report: dict[str, Any]) -> bool:
    if report["report_sha256"] != canonical_sha256(
        {k: v for k, v in report.items() if k != "report_sha256"}
    ):
        raise ValueError("PHOTO_STAGE_REPORT_CHANGED")
    observed = excluded = selected = 0
    for row in report["rows"]:
        if row["selected_images"] != len(row["decisions"]):
            return False
        for decision in row["decisions"]:
            selected += 1
            if decision["status"] == "OBSERVED":
                observed += 1
            elif decision["status"] == "EXCLUDED":
                verify_exclusion(decision["exclusion"])
                excluded += 1
            else:
                return False
    return (
        selected == report["selected_images"]
        and observed == report["observed_images"]
        and excluded == report.get("excluded_images", 0)
        and selected == observed + excluded
    )
