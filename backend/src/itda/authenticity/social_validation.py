"""Treat provider zeros, scale disagreement and unrelated posts as data states, not scores."""

from __future__ import annotations

import json
import re
from decimal import Decimal
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from itda.domain.canonical import canonical_sha256
from itda.pipeline.destination_evidence import atomic_json


def decoded_tag(row: dict[str, Any]) -> str | None:
    raw = row.get("name")
    if not isinstance(raw, str) or not raw:
        url = row.get("inputUrl") or row.get("url")
        if not isinstance(url, str):
            return None
        path = urlsplit(url).path
        if "/explore/tags/" not in path:
            return None
        raw = path.split("/explore/tags/", 1)[1].strip("/")
    return unquote(raw).lstrip("#")


def display_count_interval(raw: object) -> tuple[Decimal, Decimal] | None:
    if not isinstance(raw, str):
        return None
    normalized = raw.strip().replace(",", "")
    match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([KMGkmg만억]?)", normalized)
    if match is None:
        return None
    value = Decimal(match[1])
    unit = {"": 1, "K": 1000, "M": 1000000, "G": 1000000000, "만": 10000, "억": 100000000}[
        match[2].upper()
    ]
    center = value * unit
    if not match[2]:
        return center, center
    decimals = len(match[1].split(".")[1]) if "." in match[1] else 0
    margin = Decimal(unit) / (Decimal(10) ** decimals) / 2
    return max(Decimal(0), center - margin), center + margin


def validate_reported_count(row: dict[str, Any], *, observed_posts: int = 0) -> dict[str, Any]:
    raw = row.get("postsCount")
    base = {
        "tag": decoded_tag(row),
        "raw_count": raw,
        "display_count": row.get("posts"),
        "source_item_sha256": row.get("source_item_sha256"),
        "observed_sample_posts": observed_posts,
    }
    if type(raw) is not int or raw < 0:
        return base | {"state": "UNAVAILABLE", "value": None, "reason": "MISSING_OR_INVALID_COUNT"}
    if raw == 0:
        return base | {
            "state": "CONFLICT" if observed_posts else "UNAVAILABLE",
            "value": None,
            "reason": "ZERO_WITH_OBSERVED_POSTS" if observed_posts else "UNCONFIRMED_ZERO",
        }
    interval = display_count_interval(row.get("posts"))
    if interval is not None and not interval[0] <= raw <= interval[1]:
        return base | {
            "state": "CONFLICT",
            "value": None,
            "reason": "DISPLAY_NUMERIC_SCALE_MISMATCH",
            "display_lower": str(interval[0]),
            "display_upper": str(interval[1]),
        }
    if raw < observed_posts:
        return base | {
            "state": "CONFLICT",
            "value": None,
            "reason": "COUNT_SMALLER_THAN_OBSERVED_SAMPLE",
        }
    return base | {
        "state": "AVAILABLE_REPORTED",
        "value": raw,
        "reason": "REPORTED_COUNT_NOT_VISITOR_TOTAL",
    }


def validate_pilot(directory: Path) -> dict[str, Any]:
    manifest = json.loads((directory / "pilot-manifest.json").read_text())
    analytics = json.loads((directory / "results.json").read_text())
    posts = (
        json.loads((directory / "posts/results.json").read_text())
        if (directory / "posts/results.json").exists()
        else {"items": []}
    )
    details = (
        json.loads((directory / "details/results.json").read_text())
        if (directory / "details/results.json").exists()
        else {"items": []}
    )
    sample_by_tag: dict[str, set[str]] = {}
    for post in posts["items"]:
        tag = decoded_tag(post)
        if tag and post.get("id"):
            sample_by_tag.setdefault(tag, set()).add(post["id"])

    def inspect(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        return {
            str(decoded_tag(r)): validate_reported_count(
                r, observed_posts=len(sample_by_tag.get(str(decoded_tag(r)), set()))
            )
            for r in rows
        }

    a, b = inspect(analytics["items"]), inspect(details["items"])
    places = []
    for place in manifest["places"]:
        tag = place["primary_tag"]
        chosen = b.get(tag) or a.get(tag)
        if chosen is None:
            chosen = {
                "tag": tag,
                "state": "UNAVAILABLE",
                "value": None,
                "reason": "PRIMARY_TAG_NOT_RETURNED",
            }
        if (
            a.get(tag, {}).get("value") is not None
            and b.get(tag, {}).get("value") is not None
            and a[tag]["value"] != b[tag]["value"]
        ):
            chosen = chosen | {
                "state": "CONFLICT",
                "value": None,
                "reason": "ACTOR_COUNTS_DISAGREE",
            }
        places.append(
            {
                "place_id": place["place_id"],
                "name_ko": place["name_ko"],
                "primary_tag": tag,
                "count_observation": chosen,
                "observed_sample_posts": len(sample_by_tag.get(tag, set())),
                "place_mapping_state": "NOT_YET_VALIDATED",
                "score_eligible": False,
            }
        )
    budget = json.loads((directory / "budget.json").read_text())
    committed = sum(
        Decimal(r["actual_usd"] if r.get("actual_usd") is not None else r["reserved_usd"])
        for r in budget["runs"].values()
    )
    result = {
        "schema_version": "instagram-pilot-quality.v1",
        "manifest_sha256": manifest["manifest_sha256"],
        "places": places,
        "total_places": len(places),
        "analytics_tags": len(a),
        "primary_count_available": sum(p["count_observation"]["value"] is not None for p in places),
        "count_states": {
            s: sum(p["count_observation"]["state"] == s for p in places)
            for s in ("AVAILABLE_REPORTED", "UNAVAILABLE", "CONFLICT")
        },
        "post_sample_rows": len(posts["items"]),
        "unique_sample_posts": len({p["id"] for p in posts["items"] if p.get("id")}),
        "posts_with_caption": sum(bool(p.get("caption")) for p in posts["items"]),
        "budget_usd": budget["total_usd"],
        "committed_usd": str(committed),
        "budget_within_limit": committed <= Decimal(budget["total_usd"]),
        "human_evaluation": "EXCLUDED_BY_USER",
        "publication": "NOT_READY_PENDING_PLACE_MATCH_AND_CONTENT_ANALYSIS",
        "limitations": [
            "API success does not validate counts",
            "Matching results across related Actors are not independent ground truth",
            "Only actually returned posts are counted; samples are not a population census",
        ],
    }
    result["report_sha256"] = canonical_sha256(result)
    atomic_json(directory / "quality.json", result)
    return result
