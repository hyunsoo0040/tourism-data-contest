"""Export factual homepage examples from a verified PUBLIC release and cached official photos."""

import argparse
import hashlib
import json
from pathlib import Path

from PIL import Image, ImageOps

from itda.authenticity.auxiliary import Auxiliary
from itda.authenticity.release import load_release

# Editorial examples of three experiences, not an invented personal recommendation run.
EXAMPLES = {
    "history": ("H", ("전주 경기전", "성읍민속마을")),
    "image": ("E", ("하이커 그라운드", "해운대해수욕장")),
    "rest": ("R", ("영랑호", "천장호")),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    release, assessments = load_release(args.release)
    if release.scope != "PUBLIC":
        raise ValueError("Homepage examples require a verified PUBLIC release")
    auxiliary = Auxiliary.model_validate_json(
        (args.release / "auxiliary.json").read_bytes()
    )
    by_name = {row.source.place.name_ko: row for row in assessments}
    asset_dir = root / "web/public/tourism"
    asset_dir.mkdir(parents=True, exist_ok=True)
    result = {
        "release_sha256": release.release_sha256,
        "place_count": len(assessments),
        "release_created_at": release.created_at.isoformat(),
        "examples": {},
    }
    for kind, (axis, names) in EXAMPLES.items():
        places = []
        for name in names:
            row = by_name[name]
            place = row.source.place
            score = next(value.value for value in row.axes if value.axis == axis)
            if score is None:
                raise ValueError("An example's axis must have supporting evidence")
            description = max(
                (
                    e
                    for e in row.source.evidence
                    if e.source_role == "OFFICIAL_DESCRIPTION" and e.text
                ),
                key=lambda e: len(e.text),
            )
            photo = auxiliary.photos[place.place_id][0]
            original = next(
                path
                for path in (
                    root
                    / "artifacts/national/20260909/official-cache/images"
                    / photo.original_sha256,
                    root
                    / "artifacts/national/20260911-additional-1000/official-cache/images"
                    / photo.original_sha256,
                )
                if path.is_file()
            )
            if (
                hashlib.sha256(original.read_bytes()).hexdigest()
                != photo.original_sha256
            ):
                raise ValueError("Cached official photo hash mismatch")
            target = asset_dir / f"{photo.original_sha256}.webp"
            with Image.open(original) as opened:
                image = ImageOps.exif_transpose(opened).convert("RGB")
                image.thumbnail((960, 720))
                image.save(target, "WEBP", quality=86, method=6)
            text = description.text.strip()
            excerpt = text[:220]
            if len(text) > 220:
                sentence = excerpt.rfind("다.")
                excerpt = excerpt[: sentence + 2] if sentence >= 60 else excerpt + "…"
            places.append(
                {
                    "place_id": place.place_id,
                    "name": name,
                    "region": place.region_name,
                    "address": place.address,
                    "category": place.category,
                    "axis": axis,
                    "axis_value": score,
                    "description": excerpt,
                    "assessment_sha256": row.assessment_sha256,
                    "description_evidence_id": description.evidence_id,
                    "source_retrieved_at": description.receipt.retrieved_at.isoformat(),
                    "photo": {
                        "url": f"/tourism/{target.name}",
                        "original_url": photo.url.replace(
                            "http://tong.visitkorea.or.kr/",
                            "https://tong.visitkorea.or.kr/",
                        ),
                        "original_sha256": photo.original_sha256,
                        "asset_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                        "attribution_ko": photo.attribution_ko,
                        "license": photo.license,
                    },
                }
            )
        result["examples"][kind] = places
    output = root / "web/src/content/public-place-examples.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(
        f"Exported six examples from PUBLIC {release.release_sha256}; no network calls."
    )


if __name__ == "__main__":
    main()
