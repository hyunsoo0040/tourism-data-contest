"""Export existing official photo metadata for display; no downloads or model calls."""

import argparse
import base64
import hashlib
import json
from collections import Counter
from pathlib import Path

from itda.authenticity.display_photos import (
    DisplayPhoto,
    DisplayPhotoCatalog,
    official_image_url,
)
from itda.authenticity.release import load_release
from itda.domain.canonical import canonical_sha256


def source_photos(snapshot, place):
    """Use exact content-ID rows, including representatives rejected by analysis policy."""
    if snapshot["place"]["place_id"] != place.place_id:
        raise ValueError("DISPLAY_SOURCE_PLACE_MISMATCH")
    candidates = []
    for raw in snapshot["raw_responses"]:
        operation = raw.get("endpoint", "").split("/")[-1]
        if raw.get("provider") != "TOUR_API" or operation not in {
            "detailCommon2",
            "detailImage2",
        }:
            continue
        receipt = next(
            (r for r in snapshot["receipts"] if r["operation"] == operation), None
        )
        if not receipt or receipt["status"] != "AVAILABLE":
            continue
        body = base64.b64decode(raw["raw_body_base64"], validate=True)
        if hashlib.sha256(body).hexdigest() != receipt["response_sha256"]:
            raise ValueError("DISPLAY_SOURCE_RESPONSE_MISMATCH")
        # Read authenticated raw response bytes, rather than trusting a transformed payload.
        payload = json.loads(body)
        items = payload.get("response", {}).get("body", {}).get("items") or {}
        rows = items.get("item", []) if isinstance(items, dict) else []
        if isinstance(rows, dict):
            rows = [rows]
        for row in rows:
            if str(row.get("contentid")) != place.provider_content_id:
                continue
            rights = row.get("cpyrhtDivCd", "")
            if rights not in {f"Type{i}" for i in range(5)}:
                continue
            url = row.get(
                "firstimage" if operation == "detailCommon2" else "originimgurl"
            )
            if not url:
                continue
            try:
                url = official_image_url(url)
            except ValueError:
                continue
            candidates.append(
                (
                    operation != "detailCommon2",
                    DisplayPhoto(
                        url=url,
                        attribution_ko=f"한국관광공사 TourAPI · {place.name_ko}",
                        license=f"KOGL_TYPE_{rights[-1]}",
                        source_url=f"https://data.visitkorea.or.kr/page/{place.provider_content_id}",
                        source_record_sha256=canonical_sha256(row),
                        source_response_sha256=receipt["response_sha256"],
                        retrieved_at=receipt["retrieved_at"],
                    ),
                )
            )
    by_url = {}
    for _, photo in sorted(candidates, key=lambda item: item[0]):
        by_url.setdefault(photo.url, photo)
    return tuple(by_url.values())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument(
        "--repository", type=Path, default=Path(__file__).resolve().parents[1]
    )
    args = parser.parse_args()
    release, assessments = load_release(args.release)
    roots = {
        "initial": args.repository / "artifacts/national/20260909/analysis",
        "additional": args.repository
        / "artifacts/national/20260911-additional-1000/analysis-recovery-20260911",
    }
    photos = {}
    for assessment in assessments:
        place = assessment.source.place
        root = roots.get(place.cohort)
        if root is None:
            continue
        snapshot = json.loads(
            (root / "sources" / (place.place_id.split(":")[-1] + ".json")).read_text()
        )
        rows = source_photos(snapshot, place)
        if rows:
            photos[place.place_id] = rows
    payload = {
        "schema_version": "display-photos.v1",
        "release_sha256": release.release_sha256,
        "photos": {
            pid: [p.model_dump() for p in rows] for pid, rows in sorted(photos.items())
        },
    }
    catalog = DisplayPhotoCatalog.model_validate(
        payload | {"catalog_sha256": canonical_sha256(payload)}
    )
    target = args.release / "display-photos.json"
    target.write_text(
        json.dumps(catalog.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n"
    )
    print(
        json.dumps(
            {
                "places": len(photos),
                "photos": sum(map(len, photos.values())),
                "licenses": dict(
                    Counter(p.license for rows in photos.values() for p in rows)
                ),
                "catalog_sha256": catalog.catalog_sha256,
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
