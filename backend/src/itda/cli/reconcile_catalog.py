"""CLI for deterministic restricted catalog reconciliation."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from itda.pipeline.reconcile_catalog import (
    reconcile_crosswalk,
    reconcile_relationships,
    write_restricted_artifact,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collection-report", type=Path, required=True)
    parser.add_argument("--previous-revision", type=Path)
    parser.add_argument("--proposal-algorithm-version", required=True)
    parser.add_argument("--output-proposals", type=Path, required=True)
    parser.add_argument(
        "--output-revisions",
        type=Path,
        required=True,
        help="Restricted relationship proposal/revision review output",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.output_proposals.exists() or args.output_revisions.exists():
        raise ValueError("restricted reconciliation outputs are immutable")
    artifact = reconcile_crosswalk(
        collection_report_path=args.collection_report,
        previous_revision_path=args.previous_revision,
        proposal_algorithm_version=args.proposal_algorithm_version,
    )
    previous_relationship = None
    if args.previous_revision is not None:
        previous_relationship = args.previous_revision.with_name("relationship-review.json")
    relationships = reconcile_relationships(
        crosswalk_review=artifact,
        previous_relationship_path=previous_relationship,
        proposal_algorithm_version=args.proposal_algorithm_version,
    )
    write_restricted_artifact(
        args.output_proposals,
        artifact.model_dump(mode="json"),
    )
    write_restricted_artifact(
        args.output_revisions,
        relationships.model_dump(mode="json"),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
