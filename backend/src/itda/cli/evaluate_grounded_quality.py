"""Run the preregistered DEV source/axis experiments; never promote a release."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from itda.analysis.grounded_ablation import evaluate, preregister
from itda.cli.analyze_grounded_places import _keys
from itda.contracts.grounded_release import GroundedReleaseCandidate
from itda.contracts.visual_mood import PhotoMoodCandidateSet
from itda.photo.model_control import ModelBatchControl, ModelBatchPaused
from itda.pipeline.destination_evidence import atomic_json
from itda.pipeline.grounded_place_scoring import GroundedTextProvider


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--candidate",
        type=Path,
        default=Path("artifacts/public/catalog/grounded-public-recovery-20260909/candidate.json"),
    )
    parser.add_argument(
        "--reference-mood",
        type=Path,
        default=Path("artifacts/research/kto-context-20260909/mood-live-smoke.json"),
    )
    parser.add_argument(
        "--output", type=Path, default=Path("artifacts/evaluation/grounded-20260909")
    )
    parser.add_argument(
        "--model-cache",
        type=Path,
        default=Path("artifacts/public/catalog/grounded-source-cache/models"),
    )
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--preregister-only", action="store_true")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--semantic-cache-version", choices=("v1", "v2"), default="v1")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--retry-model-limit", action="store_true")
    parser.add_argument("--retry-model-connection", action="store_true")
    parser.add_argument("--scope", choices=("all", "sightseeing"), default="sightseeing")
    args = parser.parse_args(argv)
    for path in (args.candidate, args.reference_mood, args.output, args.model_cache):
        if any(
            "blind" in part.casefold() or part.casefold() == "sealed"
            for part in path.resolve().parts
        ):
            parser.error("BLIND/sealed paths are forbidden")
    candidate = GroundedReleaseCandidate.model_validate_json(args.candidate.read_bytes())
    reference = PhotoMoodCandidateSet.model_validate(
        json.loads(args.reference_mood.read_text())["candidate_set"]
    )
    if args.preregister_only:
        manifest = preregister(
            candidate,
            reference,
            args.output,
            cache_version=args.semantic_cache_version,
            workers=args.workers,
            scope=args.scope,
        )
        print(
            json.dumps({"status": "PREREGISTERED", "manifest_sha256": manifest["manifest_sha256"]})
        )
        return 0
    keys = _keys(args.env_file)
    try:
        result = evaluate(
            candidate,
            reference,
            output=args.output,
            cache_directory=args.model_cache,
            provider=GroundedTextProvider(
                api_key=keys.get("ZHIPUAI_API_KEY", "offline-placeholder"),
                cache_version=args.semantic_cache_version,
                batch_control=ModelBatchControl(
                    retry_limits=args.retry_model_limit,
                    retry_connections=args.retry_model_connection,
                    on_retry=lambda state: atomic_json(args.output / "model-retry.json", state),
                ),
            ),
            live=not args.offline,
            workers=args.workers,
            scope=args.scope,
        )
    except ModelBatchPaused as error:
        atomic_json(args.output / "model-paused.json", error.state)
        print(json.dumps(error.state), flush=True)
        return 75
    print(
        json.dumps(
            {
                k: v
                for k, v in result.items()
                if k
                in {
                    "status",
                    "source_rows",
                    "axis_rows",
                    "failures",
                    "source_ablation_sha256",
                    "axis_comparison_sha256",
                }
            },
            ensure_ascii=False,
        )
    )
    return 0 if result["status"] == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
