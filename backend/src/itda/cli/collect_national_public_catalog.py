"""Collect a new nationwide sample using explicit official evidence sufficiency."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import httpx

from itda.collectors.base import OfficialApiClient, RequestPolicy
from itda.collectors.kto import KorService2Client
from itda.contracts.mvp_public_catalog import OfficialDatasetPermissionMetadata
from itda.contracts.source_assessment import SourceService
from itda.pipeline.destination_evidence import OfficialSourceCache, atomic_json
from itda.pipeline.national_public_catalog import (
    NationalAttemptTransport,
    NationalProviderPaused,
    discover_nationwide,
    materialize_national_catalog,
    prior_collection_exclusions,
    read_artifact,
    select_nationwide,
)
from itda.pipeline.offline_guard import require_live_collection_allowed


def _environment(path: Path | None) -> dict[str, str]:
    result = dict(os.environ)
    if path:
        for line in path.read_text().splitlines():
            if line.lstrip().startswith("#") or "=" not in line:
                continue
            name, value = line.removeprefix("export ").split("=", 1)
            result.setdefault(name.strip(), value.strip().strip("\"'"))
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("discover", "select", "materialize", "all"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--target", type=int, default=1000)
    parser.add_argument("--exclude-collection", type=Path, action="append", default=[])
    parser.add_argument("--page-size", type=int, default=300)
    parser.add_argument("--permission", type=Path)
    parser.add_argument("--permission-snapshot", type=Path)
    parser.add_argument("--live", action="store_true")
    parser.add_argument(
        "--evaluation-sample",
        action="store_true",
        help="Separate 1..120-place automatic evaluation; prior exclusions required",
    )
    parser.add_argument(
        "--resume-provider",
        action="store_true",
        help="Resume only after provider quota/reset has been externally confirmed",
    )
    args = parser.parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=True)
    if args.command in {"discover", "select", "all"}:
        exclusions = None
        exclusion_path = args.output / "exclusions.json"
        if args.exclude_collection:
            exclusions = prior_collection_exclusions(args.exclude_collection)
            if exclusion_path.exists() and read_artifact(exclusion_path) != exclusions:
                parser.error("prior collection exclusion identity changed")
            atomic_json(exclusion_path, exclusions)
        elif exclusion_path.exists():
            exclusions = read_artifact(exclusion_path)
        require_live_collection_allowed(explicit_opt_in=args.live)
        environment = _environment(args.env_file)
        key = environment.get("TOUR_API_SERVICE_KEY")
        if not key:
            parser.error("TOUR_API_SERVICE_KEY is not configured")
        http_client = httpx.Client(
            transport=NationalAttemptTransport(
                args.output / "http-attempts.jsonl", resume_provider=args.resume_provider
            ),
            follow_redirects=False,
            trust_env=False,
        )
        clients: dict[SourceService, OfficialApiClient] = {
            SourceService.TOUR: KorService2Client(
                service_key=key,
                http_client=http_client,
                policy=RequestPolicy(timeout_seconds=30, max_attempts=1, max_backoff_seconds=2),
            )
        }
        cache = OfficialSourceCache(
            args.output / "official-cache", clients=clients, live=True, ttl_days=3650
        )
        try:
            discovery = discover_nationwide(cache, args.output, page_size=args.page_size)
            if args.command in {"select", "all"}:
                select_nationwide(
                    cache,
                    args.output,
                    discovery,
                    target_count=args.target,
                    exclusions=exclusions,
                    evaluation_sample=args.evaluation_sample,
                )
        except NationalProviderPaused as error:
            atomic_json(args.output / "paused.json", error.state)
            print(
                json.dumps(
                    {
                        "status": "PAUSED",
                        "reason": error.state.get("reason"),
                        "manual_resume_required": error.state.get("manual_resume_required"),
                        "resume_not_before": error.state.get("resume_not_before"),
                    }
                ),
                flush=True,
            )
            return 75
        finally:
            for client in clients.values():
                client.close()
            http_client.close()
    if args.command in {"materialize", "all"}:
        if args.permission is None or args.permission_snapshot is None:
            parser.error("materialization requires --permission and --permission-snapshot")
        catalog, inventory, relations = materialize_national_catalog(
            read_artifact(args.output / "selection.json"),
            read_artifact(args.output / "discovery.json"),
            permission=OfficialDatasetPermissionMetadata.model_validate_json(
                args.permission.read_bytes()
            ),
            permission_snapshot=args.permission_snapshot.read_bytes(),
        )
        for name, artifact in (
            ("catalog", catalog),
            ("evidence", inventory),
            ("relations", relations),
        ):
            atomic_json(args.output / (name + ".json"), artifact.model_dump(mode="json"))
        print(f"catalog_sha256={catalog.catalog_sha256} places={len(catalog.places)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
