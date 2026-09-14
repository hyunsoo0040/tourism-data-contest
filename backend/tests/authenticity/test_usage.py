import json

from itda.authenticity.usage import summarize
from itda.domain.canonical import canonical_sha256


def test_copied_record_is_one_exchange_and_missing_usage_is_not_fabricated(tmp_path):
    record = {
        "http_status": 200,
        "latency_seconds": 2.5,
        "raw_response": json.dumps(
            {"usage": {"prompt_tokens": 10, "completion_tokens": 7, "total_tokens": 17}}
        ),
    }
    record["record_sha256"] = canonical_sha256(record)
    for scope in ("diagnostic", "full-2000"):
        p = tmp_path / scope / "model-cache/a.attempt.json"
        p.parent.mkdir(parents=True)
        p.write_text(json.dumps(record))
    missing = {"http_status": 500, "raw_response": "unavailable"}
    missing["record_sha256"] = canonical_sha256(missing)
    recovery = tmp_path / "full-2000/photo-recovery/model-cache/b.attempt.json"
    recovery.parent.mkdir(parents=True)
    recovery.write_text(json.dumps(missing))
    r = summarize(tmp_path, tmp_path / "usage.json")
    assert r["unique_recorded_exchanges"] == 2 and r["deduplicated_cache_copies"] == 1
    assert r["reported_total_tokens"] == 17 and r["monetary_cost_usd"] is None
    assert sum(row["usage_available"] for row in r["rows"]) == 1
    assert next(row for row in r["rows"] if not row["usage_available"])["group"] == (
        "full-2000/appearance"
    )
