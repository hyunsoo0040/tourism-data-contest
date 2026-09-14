"""Compare development scenarios and audit a PUBLIC release without provider access.

Example:
  python -m itda.cli.evaluate_recommendation_quality --scenarios <dev.json>
      --release <public-release.json> --output <report.json>
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from itda.analysis.recommendation_quality import (
    DEFAULT_SCENARIO_SUITE,
    QualityEvaluationError,
    build_release_consistency_report,
    evaluate_scenarios,
)
from itda.contracts.mvp_daily_refresh import parse_daily_scored_release
from itda.contracts.place_facts import PLACE_FACT_POLICY_VERSION
from itda.domain.canonical import canonical_sha256


def _read_development_input(path: Path) -> dict[str, Any]:
    # Check the resolved target before reading; a symlink cannot bypass sealed-path rejection.
    resolved = path.resolve()
    if any("blind" in part.lower() or part.lower() == "sealed" for part in resolved.parts):
        raise QualityEvaluationError("BLIND_PATH_FORBIDDEN")
    payload = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise QualityEvaluationError("INPUT_MUST_BE_JSON_OBJECT")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenarios", type=Path, help="DEV-only scenario suite; defaults to packaged cases"
    )
    parser.add_argument(
        "--judgments", type=Path, help="Optional genuine DEV human relevance collection"
    )
    parser.add_argument(
        "--release", type=Path, help="PUBLIC scored release for actual-kernel/source audit"
    )
    parser.add_argument(
        "--previous-release", type=Path, help="Previous PUBLIC release for score drift"
    )
    parser.add_argument("--output", type=Path, help="Write report here; omitted prints JSON")
    args = parser.parse_args(argv)
    try:
        suite = (
            _read_development_input(args.scenarios) if args.scenarios else DEFAULT_SCENARIO_SUITE
        )
        judgments = _read_development_input(args.judgments) if args.judgments else None
        evaluation = evaluate_scenarios(suite, judgments=judgments)
        if args.previous_release and not args.release:
            raise QualityEvaluationError("PREVIOUS_RELEASE_REQUIRES_CURRENT_RELEASE")
        if args.release:
            from itda.contracts.recommendation import QUALITY_RECOMMENDATION_CONFIG
            from itda.domain.recommendation_projection import RECOMMENDATION_PROJECTION_VERSION_V3

            release = parse_daily_scored_release(_read_development_input(args.release))
            previous = (
                parse_daily_scored_release(_read_development_input(args.previous_release))
                if args.previous_release
                else None
            )
            report = build_release_consistency_report(
                release,
                kernel_version=QUALITY_RECOMMENDATION_CONFIG.kernel_version,
                projection_version=RECOMMENDATION_PROJECTION_VERSION_V3,
                policy_version=PLACE_FACT_POLICY_VERSION,
                scenario_suite=suite,
                previous_release=previous,
            )
            # The gate's release audit has no human judgments. Keep supplied human outcomes
            # in a separate comparison section so its authority is never silently expanded.
            if judgments is not None:
                report["development_human_comparison"] = evaluation
                report["report_sha256"] = canonical_sha256(
                    {key: value for key, value in report.items() if key != "report_sha256"}
                )
        else:
            report = {"schema_version": "recommendation-development-comparison.v1", **evaluation}
            report["report_sha256"] = canonical_sha256(report)
        rendered = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
        return 1 if report.get("consistency", {}).get("status") == "fail" else 0
    except (ValueError, OSError) as error:
        parser.error(str(error))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
