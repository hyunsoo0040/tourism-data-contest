"""Count recorded model exchanges once across cache copies; never infer billing prices."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from statistics import median
from typing import Any

from itda.domain.canonical import canonical_sha256
from itda.pipeline.destination_evidence import atomic_json

SCOPES = ("diagnostic", "development", "new-evaluation", "full-2000")


def summarize(root: Path, output: Path) -> dict[str, Any]:
    records: dict[str, tuple[dict[str, Any], str, str]] = {}
    copies = 0
    for scope in SCOPES:
        directory = root / scope
        paths = list(directory.rglob("*.attempt.json"))
        paths += list((directory / "mood/model-cache/exchanges").glob("*.json"))
        for path in sorted(paths):
            record = json.loads(path.read_text())
            key = "record_sha256" if "record_sha256" in record else "exchange_sha256"
            if record[key] != canonical_sha256({k: v for k, v in record.items() if k != key}):
                raise ValueError("MODEL_USAGE_RECORD_DIGEST_MISMATCH")
            copies += 1
            if record[key] in records:
                continue
            relative = path.relative_to(directory).parts
            stage = (
                "social-review"
                if "social" in relative and "semantic-review" in relative
                else "social"
                if "social" in relative
                else "pixel-review"
                if "photo-review" in relative
                else "appearance"
                if "appearance" in relative or "photo-recovery" in relative
                else "text-review"
                if "semantic-review" in relative
                else "repair"
                if "repair" in relative
                else "mood"
                if "mood" in relative
                else "text"
            )
            records[record[key]] = (record, scope, stage)
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record, scope, stage in records.values():
        try:
            body = json.loads(record["raw_response"])
        except (ValueError, TypeError):
            body = {}
        raw_usage = body.get("usage", {}) if isinstance(body, dict) else {}
        usage = raw_usage if isinstance(raw_usage, dict) else {}
        keys = ("prompt_tokens", "completion_tokens", "total_tokens")
        valid = all(type(usage.get(k)) is int and usage[k] >= 0 for k in keys)
        groups[scope + "/" + stage].append(
            {
                "status": record["http_status"],
                "has_usage": valid,
                **{k: usage[k] if valid else 0 for k in keys},
                "latency": record.get("latency_seconds"),
            }
        )
    rows = []
    for group, items in sorted(groups.items()):
        latency = [r["latency"] for r in items if isinstance(r["latency"], (int, float))]
        rows.append(
            {
                "group": group,
                "recorded_exchanges": len(items),
                "usage_available": sum(r["has_usage"] for r in items),
                **{
                    "reported_" + k: sum(r[k] for r in items)
                    for k in ("prompt_tokens", "completion_tokens", "total_tokens")
                },
                "median_recorded_request_seconds": round(median(latency), 3) if latency else None,
                "http_statuses": dict(Counter(str(r["status"]) for r in items)),
            }
        )
    report = {
        "version": "authenticity-recorded-model-usage-v1",
        "observed_at": datetime.now(UTC).isoformat(),
        "physical_record_files": copies,
        "unique_recorded_exchanges": len(records),
        "deduplicated_cache_copies": copies - len(records),
        "rows": rows,
        "reported_total_tokens": sum(r["reported_total_tokens"] for r in rows),
        "monetary_cost_usd": None,
        "billing_reason": "PROVIDER_BILLING_NOT_RETURNED_NO_PRICE_ASSUMPTION",
        "scope": "RECORDED_PUBLIC_BATCH_EXCHANGES_ONLY",
        "excludes": [
            "private photo endpoint requests",
            "transport retries with no retained response record",
        ],
        "caution": "Parallel request latencies are not additive wall-clock duration. "
        "Cache copies are not new calls.",
    }
    report["report_sha256"] = canonical_sha256(report)
    atomic_json(output, report)
    return report
