"""Explicit live-capable seven-source diagnostic; defaults to a provider-free plan."""

from __future__ import annotations

import argparse
import json
import os
import re
from datetime import UTC, date, datetime
from pathlib import Path

from itda.contracts.grounded_recommendation import GroundedTripInput
from itda.contracts.mvp_public_catalog import PublicPlaceCatalog
from itda.contracts.tourism_context import TOURISM_CONSUMERS
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.tourism.registry import ProductionTourismRegistry, _periods
from itda.tourism.settings import TourismSettings


def _environment(env_files: list[Path]) -> dict[str, str]:
    environment = dict(os.environ)
    for path in env_files:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:]
            name, separator, value = line.partition("=")
            if not separator or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name.strip()) is None:
                raise ValueError("invalid tourism environment file")
            name = name.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                value = value[1:-1]
            if (
                name == "TOUR_API_SERVICE_KEY"
                or name == "ITDA_TOUR_API_SERVICE_KEY_FILE"
                or name.startswith("ITDA_TOURISM_")
            ):
                environment[name] = value
    return environment


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--live",
        action="store_true",
        help="Make bounded official API requests; omitted means dry-run.",
    )
    parser.add_argument(
        "--catalog",
        type=Path,
        default=Path("artifacts/public/catalog/public-place-catalog-v1.json"),
    )
    parser.add_argument("--env-file", type=Path, action="append", default=[])
    parser.add_argument("--place-id", action="append", default=[])
    parser.add_argument("--visit-date", type=date.fromisoformat)
    parser.add_argument("--visitor-start", type=date.fromisoformat)
    parser.add_argument("--visitor-end", type=date.fromisoformat)
    parser.add_argument("--demand-month")
    parser.add_argument("--related-month")
    parser.add_argument(
        "--output", type=Path, default=Path("artifacts/research/tourism-source-verification")
    )
    args = parser.parse_args(argv)
    try:
        environment = _environment(args.env_file)
        settings = TourismSettings.from_environment(environment)
        overrides = {"enabled": args.live}
        for argument_name, target in (
            ("visitor_start", "visitor_reference_start"),
            ("visitor_end", "visitor_reference_end"),
            ("demand_month", "demand_reference_month"),
            ("related_month", "related_reference_month"),
        ):
            if getattr(args, argument_name) is not None:
                overrides[target] = getattr(args, argument_name)
        settings = TourismSettings.model_validate({**settings.model_dump(), **overrides})
        catalog = PublicPlaceCatalog.model_validate_json(args.catalog.read_bytes())
        known = tuple(row.place_id for row in catalog.places)
        place_ids = tuple(args.place_id) if args.place_id else known[:5]
        if not set(place_ids) <= set(known) or len(place_ids) > 5:
            raise ValueError("diagnostic places must be canonical and at most five")
        now = datetime.now(UTC)
        if not args.live:
            print(
                json.dumps(
                    {
                        "mode": "DRY_RUN",
                        "provider_requests": 0,
                        "places": len(place_ids),
                        "source_consumers": {
                            service.value: consumer
                            for service, consumer in TOURISM_CONSUMERS.items()
                        },
                        "reference_periods": _periods(settings, now).model_dump(mode="json"),
                        "http_concurrency": settings.http_concurrency,
                        "model_session_limit": settings.model_session_limit,
                    },
                    ensure_ascii=False,
                )
            )
            return 0
        root = args.output
        root.mkdir(parents=True, exist_ok=False)
        attempts = root / "attempts"
        attempts.mkdir()
        records: list[dict[str, object]] = []

        def observe(event: dict[str, object], body: bytes | None) -> None:
            number = len(records) + 1
            record = {**event, "observed_at": datetime.now(UTC).isoformat()}
            if body is not None:
                path = attempts / f"{number:05d}.body"
                path.write_bytes(body)
                record["response_path"] = str(path.relative_to(root))
            else:
                record["response_path"] = None
            (attempts / f"{number:05d}.json").write_bytes(canonical_json_bytes(record))
            records.append(record)

        registry = ProductionTourismRegistry.from_catalog(
            catalog, settings=settings, environ=environment, observer=observe
        )
        try:
            context, sources = registry.context_with_sources(
                run_id="diagnostic:tourism-sources",
                place_ids=place_ids,
                trip_input=GroundedTripInput(visit_date=args.visit_date),
                eligible_place_ids=known,
                purpose="MIXED",
            )
        finally:
            registry.close()
        (root / "context.json").write_bytes(canonical_json_bytes(context.model_dump(mode="json")))
        source_root = root / "sources"
        source_root.mkdir()
        for source in sources:
            (source_root / f"{canonical_sha256(source)}.json").write_bytes(
                canonical_json_bytes(source)
            )
        report = {
            "schema_version": "tourism-source-verification.v1",
            "mode": "LIVE",
            "created_at": now.isoformat(),
            "context_sha256": context.context_sha256,
            "attempt_count": len(records),
            "source_health": [row.model_dump(mode="json") for row in context.source_health],
            "settings": settings.model_dump(mode="json"),
            "source_snapshot_sha256": list(context.source_snapshot_sha256),
        }
        report["report_sha256"] = canonical_sha256(report)
        (root / "report.json").write_bytes(canonical_json_bytes(report))
        print(
            json.dumps(
                {
                    "mode": "LIVE",
                    "attempt_count": len(records),
                    "report": str(root / "report.json"),
                    "health": {row.service.value: row.state for row in context.source_health},
                },
                ensure_ascii=False,
            )
        )
        return 0
    except (ValueError, OSError) as error:
        # Never echo source URLs with keys, credential values or private paths.
        print(
            json.dumps(
                {
                    "status": "FAILED",
                    "error_type": type(error).__name__,
                    "message": "Tourism source verification failed; check configuration and paths.",
                }
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
