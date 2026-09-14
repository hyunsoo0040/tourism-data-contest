"""Analyze the new authenticity construct from explicitly frozen source membership."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from itda.authenticity.batch import (
    prepare_development,
    prepare_diagnostic,
    run_photo_batch,
    run_review_batch,
    run_text_batch,
)
from itda.cli.collect_national_public_catalog import _environment


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=(
            "prepare-diagnostic",
            "prepare-development",
            "analyze",
            "photos",
            "review",
            "social",
            "photo-review",
            "evaluate",
            "sensitivity",
            "prepare-full",
            "prepare-evaluation",
            "evaluation-moods",
            "evaluate-new",
            "recover-format",
        ),
    )
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument(
        "--output", type=Path, default=Path("artifacts/authenticity-v1/20260911/diagnostic")
    )
    parser.add_argument("--manifest", type=Path)
    parser.add_argument(
        "--collection",
        type=Path,
        default=Path("artifacts/national/20260911-authenticity-evaluation-60"),
    )
    parser.add_argument("--env-file", type=Path, default=Path(".secrets/itda-api-all.env"))
    parser.add_argument("--workers", type=int, default=5)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--offline-sources", action="store_true")
    parser.add_argument(
        "--pilot", type=Path, default=Path("artifacts/authenticity-v1/20260911/instagram-pilot")
    )
    parser.add_argument(
        "--photo-condition", choices=("text", "photo-er", "photo-her"), default="photo-er"
    )
    args = parser.parse_args()
    if args.command == "prepare-full":
        from itda.authenticity.full_batch import prepare

        manifest = prepare(args.repository, args.output)
        print(
            json.dumps(
                {"places": len(manifest["members"]), "manifest_sha256": manifest["manifest_sha256"]}
            )
        )
        return 0
    if args.command == "prepare-development":
        manifest = prepare_development(args.repository, args.output)
        print(
            json.dumps(
                {"places": len(manifest["members"]), "manifest_sha256": manifest["manifest_sha256"]}
            )
        )
        return 0
    if args.command == "prepare-diagnostic":
        manifest = prepare_diagnostic(args.repository, args.output)
        print(
            json.dumps(
                {"places": len(manifest["members"]), "manifest_sha256": manifest["manifest_sha256"]}
            )
        )
        return 0
    if args.command == "evaluate-new":
        from itda.authenticity.heldout import evaluate as evaluate_new

        report = evaluate_new(args.output, args.repository)
        print(
            json.dumps(
                {"report_sha256": report["report_sha256"], "conditions": report["conditions"]}
            )
        )
        return 0
    if args.command == "sensitivity":
        from itda.authenticity.sensitivity import evaluate as evaluate_sensitivity

        report = evaluate_sensitivity(args.output)
        print(
            json.dumps(
                {
                    "report_sha256": report["report_sha256"],
                    "duplicate_value_violations": report["duplicate_value_violations"],
                }
            )
        )
        return 0
    if args.command == "evaluate":
        from itda.authenticity.evaluation import evaluate

        report = evaluate(args.output)
        print(
            json.dumps(
                {"report_sha256": report["report_sha256"], "scenarios": report["scenario_count"]}
            )
        )
        return 0
    env = _environment(args.env_file)
    if args.command == "recover-format":
        from itda.authenticity.format_recovery import recover

        report = recover(args.output, api_key=env.get("ZHIPUAI_API_KEY", ""), live=args.live)
        print(
            json.dumps(
                {"recovered": report["recovered"], "still_unavailable": report["still_unavailable"]}
            )
        )
        return 0 if not report["still_unavailable"] else 2
    if args.command == "evaluation-moods":
        from itda.authenticity.evaluation_moods import run as run_evaluation_moods

        report = run_evaluation_moods(
            directory=args.output,
            collection=args.collection,
            api_key=env.get("ZHIPUAI_API_KEY", ""),
            workers=args.workers,
            live=args.live,
        )
        print(
            json.dumps({"places": report["places"], "observed_images": report["observed_images"]})
        )
        return 0
    if args.command == "prepare-evaluation":
        if not args.live and not args.offline_sources:
            parser.error("prepare-evaluation requires explicit --live for official collection")
        from itda.authenticity.evaluation_batch import prepare as prepare_evaluation
        from itda.pipeline.national_public_catalog import NationalProviderPaused

        try:
            manifest = prepare_evaluation(
                repository=args.repository,
                directory=args.output,
                collection=args.collection,
                keys=env,
                offline=args.offline_sources,
            )
        except NationalProviderPaused:
            print(
                json.dumps(
                    {"status": "PAUSED", "reason": "OFFICIAL_SOURCE_QUOTA_NO_AUTOMATIC_RETRY"}
                )
            )
            return 75
        print(
            json.dumps(
                {"places": len(manifest["members"]), "manifest_sha256": manifest["manifest_sha256"]}
            )
        )
        return 0
    if args.command == "photo-review":
        from itda.authenticity.photo_review import apply, run

        report = run(
            directory=args.output,
            api_key=env.get("ZHIPUAI_API_KEY", ""),
            workers=args.workers,
            live=args.live,
        )
        fused = apply(args.output)
        print(
            json.dumps(
                {
                    "images": report["images"],
                    "decisions": report["decisions"],
                    "places": fused["places"],
                }
            )
        )
        return 0
    if args.command == "social":
        from itda.authenticity.social_batch import run_social_batch

        report = run_social_batch(
            directory=args.output,
            pilot_directory=args.pilot,
            api_key=env.get("ZHIPUAI_API_KEY", ""),
            photo_condition=args.photo_condition,
            workers=args.workers,
            live=args.live,
        )
        print(json.dumps({"places": report["places"], "caption_places": report["caption_places"]}))
        return 0
    if args.command == "review":
        report = run_review_batch(
            manifest_path=args.manifest or args.output / "manifest.json",
            directory=args.output,
            api_key=env.get("ZHIPUAI_API_KEY", ""),
            workers=args.workers,
            live=args.live,
        )
        print(json.dumps({"reviewed_places": report["places"], "scope": report["scope"]}))
        return 0
    if args.command == "photos":
        from itda.authenticity.photo_recovery import photo_stage_complete

        report = run_photo_batch(
            manifest_path=args.manifest or args.output / "manifest.json",
            directory=args.output,
            repository=args.repository,
            api_key=env.get("ZHIPUAI_API_KEY", ""),
            workers=args.workers,
            live=args.live,
        )
        print(
            json.dumps(
                {
                    "selected_images": report["selected_images"],
                    "observed_images": report["observed_images"],
                    "excluded_images": report["excluded_images"],
                }
            )
        )
        return 0 if photo_stage_complete(report) else 2
    report = run_text_batch(
        manifest_path=args.manifest or args.output / "manifest.json",
        directory=args.output,
        api_key=env.get("ZHIPUAI_API_KEY", ""),
        workers=args.workers,
        live=args.live,
    )
    print(
        json.dumps(
            {
                "status": "COMPLETE",
                "statuses": report["statuses"],
                "report_sha256": report["report_sha256"],
            }
        )
    )
    return 0 if report["statuses"]["UNAVAILABLE"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
