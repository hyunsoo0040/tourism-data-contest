"""Observed public posts and validated count snapshots, linked to a specific place."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from itda.authenticity.contracts import Evidence, Receipt, SourceBundle
from itda.authenticity.social_validation import decoded_tag
from itda.authenticity.sources import seal_evidence
from itda.domain.canonical import canonical_sha256
from itda.pipeline.destination_evidence import atomic_json


def normalized(text: str) -> str:
    return re.sub(r"[^\w]", "", text).casefold()


def region_markers(region: str) -> tuple[str, ...]:
    result = []
    for token in region.split():
        marker = re.sub(r"(특별자치도|특별자치시|통합특별시|특별시|광역시|도|시|군|구)$", "", token)
        if len(marker) >= 2:
            result.append(marker)
    return tuple(result)


def match_post(post: dict[str, Any], place: dict[str, Any]) -> dict[str, Any]:
    tag = decoded_tag(post)
    target = place["primary_tag"]
    if tag != target:
        return {
            "state": "NOT_MATCHED",
            "reason": "POST_WAS_NOT_RETURNED_FOR_PRIMARY_TAG",
            "basis": [],
        }
    caption = normalized(post.get("caption", ""))
    location = normalized(post.get("locationName", ""))
    markers = region_markers(place["region"])
    named = normalized(target) in caption
    areas = [marker for marker in markers if normalized(marker) in caption]
    # This is a conservative, auditable association rule, not proof of a visit.
    if named and areas:
        return {
            "state": "VERIFIED",
            "reason": "EXACT_PRIMARY_TAG_AND_CAPTION_NAME_REGION",
            "basis": [
                f"조회 태그: {target}",
                f"본문/해시태그의 명칭: {target}",
                "본문의 행정구역 단서: " + ", ".join(areas),
            ],
            "interpretation": "AUTOMATED_ASSOCIATION_NOT_VERIFIED_VISIT",
        }
    return {
        "state": "AMBIGUOUS",
        "reason": "INSUFFICIENT_PLACE_CONTEXT",
        "basis": [f"조회 태그: {target}", f"반환 위치 표기: {location}"],
        "interpretation": "HASHTAG_ALONE_IS_NOT_PLACE_IDENTITY",
    }


def _post_role(post: dict[str, Any]) -> str:
    tags = {str(t).lstrip("#").casefold() for t in post.get("hashtags", []) if isinstance(t, str)}
    if tags & {"광고", "협찬", "유료광고", "제품제공", "광고포함"}:
        return "ADVERTISEMENT"
    return "UNCLASSIFIED"


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    offset = result.utcoffset()
    return result if offset is not None and offset.total_seconds() == 0 else None


def _public_post_url(post: dict[str, Any]) -> str | None:
    url = post.get("url")
    if not isinstance(url, str):
        return None
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in {"www.instagram.com", "instagram.com"}:
        return None
    if not parsed.path.startswith(("/p/", "/reel/")):
        return None
    return "https://www.instagram.com" + parsed.path


def build_pilot_evidence(directory: Path) -> dict[str, tuple[Evidence, ...]]:
    manifest = json.loads((directory / "pilot-manifest.json").read_text())
    quality = json.loads((directory / "quality.json").read_text())
    posts = json.loads((directory / "posts/results.json").read_text())
    details = json.loads((directory / "details/results.json").read_text())
    for record, key in ((manifest, "manifest_sha256"), (quality, "report_sha256")):
        if record[key] != canonical_sha256({k: v for k, v in record.items() if k != key}):
            raise ValueError("SOCIAL_INPUT_DIGEST_MISMATCH")
    if quality["manifest_sha256"] != manifest["manifest_sha256"]:
        raise ValueError("SOCIAL_VALIDATION_MANIFEST_MISMATCH")
    q_by_place = {p["place_id"]: p for p in quality["places"]}
    d_by_tag = {decoded_tag(r): (i, r) for i, r in enumerate(details["items"])}
    p_by_tag: dict[str, list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    for index, post in enumerate(posts["items"]):
        tag = decoded_tag(post)
        if tag:
            p_by_tag[tag].append((index, post))
    output = {}
    audit = []
    for place in manifest["places"]:
        linked = []
        for index, post in p_by_tag.get(place["primary_tag"], []):
            match = match_post(post, place)
            audit.append({"place_id": place["place_id"], "post_id": post.get("id"), **match})
            if match["state"] == "VERIFIED" and post.get("caption"):
                linked.append((index, post, match))
        records = []
        # Same place, same post ID, one contribution. Ordering is chronological,
        # never by favorable sentiment, likes or follower count.
        unique = {post["id"]: (i, post, match) for i, post, match in linked}
        chosen = sorted(
            unique.values(),
            key=lambda r: (str(r[1].get("timestamp", "")), r[1]["id"]),
            reverse=True,
        )[:3]
        for index, post, match in chosen:
            material = {
                "retained_post": post,
                "matching": match,
                "place_id": place["place_id"],
                "dataset_response_page_sha256": posts["response_page_sha256"][index // 120],
            }
            material_sha = canonical_sha256(material)
            atomic_json(directory / "source-records" / (material_sha + ".json"), material)
            receipt = Receipt.model_validate(
                {
                    "provider": "APIFY_INSTAGRAM",
                    "operation": "hashtagPosts",
                    "provider_record_id": post["id"],
                    "retrieved_at": posts["retrieved_at"],
                    "source_modified_at": _timestamp(post.get("timestamp")),
                    "request_sha256": posts["request_sha256"],
                    "response_sha256": posts["response_page_sha256"][index // 120],
                    "source_record_sha256": material_sha,
                    "source_uri": _public_post_url(post),
                    "actor_id": posts["actor_id"],
                    "actor_build_id": posts["actor_build_id"],
                    "actor_run_id": posts["run_id"],
                }
            )
            records.append(
                seal_evidence(
                    {
                        "evidence_id": "social-post:" + material_sha,
                        "place_id": place["place_id"],
                        "modality": "TEXT",
                        "state": "AVAILABLE",
                        "receipt": receipt,
                        "place_match": "VERIFIED",
                        "match_basis": tuple(match["basis"]),
                        "source_role": _post_role(post),
                        "field": "caption",
                        "text": post["caption"][:8000],
                    }
                )
            )
        pair = d_by_tag.get(place["primary_tag"])
        if pair and chosen:
            index, raw = pair
            count = q_by_place[place["place_id"]]["count_observation"]
            material = {
                "retained_count": raw,
                "validated_count": count,
                "place_id": place["place_id"],
                "matching_post_records": [r.evidence_id for r in records],
            }
            material_sha = canonical_sha256(material)
            atomic_json(directory / "source-records" / (material_sha + ".json"), material)
            receipt = Receipt.model_validate(
                {
                    "provider": "APIFY_INSTAGRAM",
                    "operation": "hashtagDetails",
                    "provider_record_id": str(raw.get("id", place["primary_tag"])),
                    "retrieved_at": details["retrieved_at"],
                    "request_sha256": details["request_sha256"],
                    "response_sha256": details["response_page_sha256"][index // 120],
                    "source_record_sha256": material_sha,
                    "source_uri": raw.get("url"),
                    "actor_id": details["actor_id"],
                    "actor_build_id": details["actor_build_id"],
                    "actor_run_id": details["run_id"],
                }
            )
            records.append(
                seal_evidence(
                    {
                        "evidence_id": "social-count:" + material_sha,
                        "place_id": place["place_id"],
                        "modality": "COUNT",
                        "state": "AVAILABLE" if count["value"] is not None else "AMBIGUOUS",
                        "receipt": receipt,
                        "place_match": "VERIFIED",
                        "match_basis": tuple(chosen[0][2]["basis"]),
                        "source_role": "UNCLASSIFIED",
                        "field": "postsCount",
                        "reported_count": count["value"],
                        "reported_count_raw": str(raw.get("postsCount")),
                        "primary_tag": place["primary_tag"],
                    }
                )
            )
        output[place["place_id"]] = tuple(records)
        atomic_json(
            directory / "evidence" / (place["place_id"].split(":")[-1] + ".json"),
            [r.model_dump(mode="json") for r in records],
        )
    report = {
        "schema_version": "instagram-place-association.v1",
        "manifest_sha256": manifest["manifest_sha256"],
        "matching_rule": "PRIMARY_TAG_PLUS_CAPTION_NAME_AND_REGION-v1",
        "human_evaluation": "EXCLUDED_BY_USER",
        "post_decisions": audit,
        "places_with_caption_evidence": sum(
            any(e.modality == "TEXT" for e in records) for records in output.values()
        ),
        "caption_evidence_count": sum(
            sum(e.modality == "TEXT" for e in records) for records in output.values()
        ),
        "places_with_usable_count": sum(
            any(e.modality == "COUNT" and e.state == "AVAILABLE" for e in records)
            for records in output.values()
        ),
        "interpretation": "AUTOMATED_ASSOCIATION_NOT_VISIT_VERIFICATION_OR_HUMAN_LABEL",
    }
    report["report_sha256"] = canonical_sha256(report)
    atomic_json(directory / "association-report.json", report)
    return output


def load_pilot_evidence(directory: Path, source: SourceBundle) -> tuple[Evidence, ...]:
    path = directory / "evidence" / (source.place.place_id.split(":")[-1] + ".json")
    if not path.exists():
        return ()
    records = tuple(Evidence.model_validate(e) for e in json.loads(path.read_text()))
    if any(e.place_id != source.place.place_id for e in records):
        raise ValueError("SOCIAL_EVIDENCE_PLACE_MISMATCH")
    return records
