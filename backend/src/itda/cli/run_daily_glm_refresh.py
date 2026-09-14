"""Run the bounded grounded daily scheduler; retain historical raw test helpers."""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import UTC, date, datetime
from pathlib import Path
from typing import NoReturn

from itda.catalog_paths import (
    NATIONAL_CATALOG_PATH,
    NATIONAL_EVIDENCE_PATH,
    NATIONAL_RELATIONS_PATH,
    is_national_candidate,
    is_national_catalog,
)
from itda.contracts.mvp_daily_refresh import (
    DAILY_REFRESH_AUTHORITY_V2,
    DailyRefreshRunStatus,
)
from itda.contracts.mvp_place_scoring import PublicScoringRequest
from itda.contracts.mvp_public_catalog import (
    PublicEvidenceInventory,
    PublicPlaceCatalog,
    PublicPlaceRelations,
)
from itda.db.assessment_release import AssessmentReleaseRepository
from itda.db.mvp_release_overlay import (
    ActiveReleaseOverlayResolver,
    DailyRefreshStore,
    DailyReleaseOverlayReader,
)
from itda.db.session import create_database_engine, create_session_factory
from itda.pipeline.daily_public_input import LiveDailyTourApiProvider
from itda.pipeline.daily_refresh import due_run_date, next_run_at, run_daily_refresh
from itda.pipeline.mvp_place_scoring import (
    GlmCodingScoringTransport,
    ScoringTransport,
    require_live_network_allowed,
)
from itda.pipeline.offline_guard import require_live_collection_allowed

LOGGER = logging.getLogger("itda.daily_glm_refresh")
_ROOT = Path(__file__).resolve().parents[4]


class _NationalDailyStore(AssessmentReleaseRepository):
    def __init__(self, factory, catalog: PublicPlaceCatalog) -> None:
        super().__init__(factory)
        self._catalog = catalog

    def load_active(self):
        candidate = super().load_active()
        return (
            candidate
            if candidate is not None and is_national_candidate(candidate, self._catalog)
            else None
        )


class DeferredGlmTransport:
    def __init__(self) -> None:
        self._transport: GlmCodingScoringTransport | None = None

    def score(
        self,
        request: PublicScoringRequest,
        *,
        timeout_seconds: int,
        max_tokens: int,
    ) -> bytes:
        if self._transport is None:
            api_key = _secret("ZHIPUAI_API_KEY", "ITDA_ZHIPUAI_API_KEY_FILE")
            self._transport = GlmCodingScoringTransport(api_key)
        return self._transport.score(
            request,
            timeout_seconds=timeout_seconds,
            max_tokens=max_tokens,
        )

    def close(self) -> None:
        if self._transport is not None:
            self._transport.close()


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError("daily GLM refresh configuration rejected")
    return value


def _secret(environment: str, file_environment: str) -> str:
    path = os.environ.get(file_environment, "").strip()
    value = (
        Path(path).read_text(encoding="utf-8").strip()
        if path
        else os.environ.get(environment, "").strip()
    )
    if not value:
        raise RuntimeError("daily GLM refresh secret configuration rejected")
    return value


def _validate_authority() -> None:
    if os.environ.get("ITDA_DAILY_GLM_REFRESH_ENABLED", "").strip() != "1":
        raise RuntimeError("daily GLM refresh is disabled")
    if (
        os.environ.get("ITDA_DAILY_GLM_REFRESH_AUTHORITY_SHA256", "").strip()
        != DAILY_REFRESH_AUTHORITY_V2.authority_sha256
    ):
        raise RuntimeError("daily GLM refresh authority rejected")


def _load_artifacts() -> tuple[
    PublicPlaceCatalog,
    PublicEvidenceInventory,
    PublicPlaceRelations,
]:
    catalog_path = Path(
        os.environ.get(
            "ITDA_PUBLIC_PLACE_CATALOG_PATH",
            _ROOT / NATIONAL_CATALOG_PATH,
        )
    )
    evidence_path = Path(
        os.environ.get(
            "ITDA_PUBLIC_EVIDENCE_INVENTORY_PATH",
            _ROOT / NATIONAL_EVIDENCE_PATH,
        )
    )
    relations_path = Path(
        os.environ.get(
            "ITDA_PUBLIC_PLACE_RELATIONS_PATH",
            _ROOT / NATIONAL_RELATIONS_PATH,
        )
    )
    return (
        PublicPlaceCatalog.model_validate_json(catalog_path.read_bytes()),
        PublicEvidenceInventory.model_validate_json(evidence_path.read_bytes()),
        PublicPlaceRelations.model_validate_json(relations_path.read_bytes()),
    )


def _safe_log(event: str, **fields: object) -> None:
    allowed = {
        "run_date",
        "status",
        "changed_count",
        "failed_count",
        "call_count",
        "release_sha256",
        "safe_reason",
        "next_run_at",
    }
    payload = {"event": event, **{key: value for key, value in fields.items() if key in allowed}}
    LOGGER.info(json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str))


def _sleep_until(target: datetime) -> None:
    seconds = max(1.0, (target - datetime.now(UTC)).total_seconds())
    time.sleep(min(seconds, 15.0))


def _run_one(
    *,
    run_date: date,
    store: DailyRefreshStore,
    reader: DailyReleaseOverlayReader,
    active_resolver: ActiveReleaseOverlayResolver,
    catalog: PublicPlaceCatalog,
    evidence: PublicEvidenceInventory,
    relations: PublicPlaceRelations,
    tour_api_key: str,
    preclaimed: bool = False,
) -> None:
    if not preclaimed:
        current = reader.status()
        if current is not None and current.run_date == run_date:
            if str(current.status) == "RUNNING":
                store.interrupt(run_date=run_date)
            return
    provider = LiveDailyTourApiProvider(
        service_key=tour_api_key,
        timeout_seconds=float(os.environ.get("ITDA_DAILY_TOUR_API_TIMEOUT_SECONDS", "15")),
    )

    def scoring_transport_factory() -> ScoringTransport:
        return DeferredGlmTransport()

    try:
        outcome = run_daily_refresh(
            run_date=run_date,
            collected_at=datetime.now(UTC),
            catalog=catalog,
            evidence_inventory=evidence,
            relations=relations,
            provider=provider,
            store=store,
            active_release_resolver=active_resolver,
            scoring_transport_factory=scoring_transport_factory,
            preclaimed=preclaimed,
        )
    finally:
        provider.close()
    if outcome is not None:
        _safe_log(
            "daily_glm_refresh_finished",
            run_date=outcome.run_date,
            status=outcome.status,
            changed_count=outcome.changed_count,
            failed_count=outcome.failed_count,
            call_count=outcome.call_count,
            release_sha256=outcome.release_sha256,
            safe_reason=outcome.safe_reason,
        )


def _run_recollection_command(
    *,
    store: DailyRefreshStore,
    reader: DailyReleaseOverlayReader,
    active_resolver: ActiveReleaseOverlayResolver,
    catalog: PublicPlaceCatalog,
    evidence: PublicEvidenceInventory,
    relations: PublicPlaceRelations,
    tour_api_key: str,
) -> bool:
    command = store.claim_recollection(lease_seconds=60)
    if command is None:
        return False
    _run_one(
        run_date=command.run_date,
        store=store,
        reader=reader,
        active_resolver=active_resolver,
        catalog=catalog,
        evidence=evidence,
        relations=relations,
        tour_api_key=tour_api_key,
        preclaimed=True,
    )
    status = reader.status()
    if status is None or status.run_date != command.run_date:
        store.complete_recollection(
            command_id=command.command_id,
            status="REJECTED",
            safe_reason="RECOLLECTION_STATE_CHANGED",
        )
        return True
    successful = status.status in {
        DailyRefreshRunStatus.BASELINE_RECORDED,
        DailyRefreshRunStatus.NO_CHANGES,
        DailyRefreshRunStatus.RELEASE_ACTIVATED,
    }
    store.complete_recollection(
        command_id=command.command_id,
        status="SUCCEEDED" if successful else "FAILED",
        safe_reason=None if successful else status.safe_reason or str(status.status),
    )
    return True


def _configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    # Embedded runs may follow Alembic's fileConfig, which disables preexisting
    # named loggers. Restore our bounded event logger without enabling HTTP URLs.
    LOGGER.disabled = False
    LOGGER.setLevel(logging.INFO)
    for name in ("httpx", "httpcore"):
        logger = logging.getLogger(name)
        logger.disabled = False
        logger.setLevel(logging.WARNING)


def _run_grounded_scheduler() -> NoReturn:
    """Stage complete grounded pairs and promote only with measured gate evidence."""
    import argparse
    from contextlib import ExitStack
    from urllib.parse import unquote
    from zoneinfo import ZoneInfo

    from itda.pipeline.destination_evidence import OfficialSourceCache, official_clients
    from itda.pipeline.destination_mood import CachedDestinationMoodProvider
    from itda.pipeline.grounded_daily_refresh import read_promotion_evidence, run_grounded_daily
    from itda.pipeline.grounded_place_scoring import GroundedTextProvider

    parser = argparse.ArgumentParser(
        description="Daily grounded complete-pair analysis; stage until measured gates pass"
    )
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--run-date", type=date.fromisoformat)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--provider-control-root", type=Path)
    parser.add_argument("--resume-provider", action="store_true")
    parser.add_argument(
        "--workers", type=int, default=int(os.environ.get("ITDA_GROUNDED_DAILY_WORKERS", "4"))
    )
    parser.add_argument(
        "--gate",
        type=Path,
        default=Path(os.environ["ITDA_GROUNDED_DAILY_GATE_FILE"])
        if os.environ.get("ITDA_GROUNDED_DAILY_GATE_FILE")
        else None,
    )
    parser.add_argument(
        "--reports",
        type=Path,
        default=Path(os.environ["ITDA_GROUNDED_DAILY_REPORT_DIR"])
        if os.environ.get("ITDA_GROUNDED_DAILY_REPORT_DIR")
        else None,
    )
    args = parser.parse_args()
    if not 1 <= args.workers <= 32:
        parser.error("workers must be1..32; default4 reserves online capacity")
    if args.run_date and not args.once:
        parser.error("a historical run date requires --once")
    if bool(args.gate) != bool(args.reports):
        parser.error("--gate and --reports must be provided together")
    if not args.offline:
        require_live_collection_allowed(explicit_opt_in=True)
        require_live_network_allowed()
    tour_key = (
        "offline-placeholder"
        if args.offline
        else _secret("TOUR_API_SERVICE_KEY", "ITDA_TOUR_API_SERVICE_KEY_FILE")
    )
    model_key = (
        "offline-placeholder"
        if args.offline
        else _secret("ZHIPUAI_API_KEY", "ITDA_ZHIPUAI_API_KEY_FILE")
    )
    odii_file = os.environ.get("ITDA_ODII_SERVICE_KEY_FILE")
    odii_key = (
        Path(odii_file).read_text().strip() if odii_file else os.environ.get("ODII_SERVICE_KEY")
    )
    catalog_path = Path(
        os.environ.get(
            "ITDA_PUBLIC_PLACE_CATALOG_PATH",
            str(_ROOT / NATIONAL_CATALOG_PATH),
        )
    )
    catalog = PublicPlaceCatalog.model_validate_json(catalog_path.read_bytes())
    if not is_national_catalog(catalog):
        raise RuntimeError("national daily refresh requires the current national catalog")
    engine = create_database_engine(_required("ITDA_DAILY_GLM_REFRESH_DATABASE_URL"))
    factory = create_session_factory(engine)
    store = _NationalDailyStore(factory, catalog)
    root = Path(
        os.environ.get(
            "ITDA_GROUNDED_DAILY_OUTPUT_ROOT",
            str(_ROOT / "artifacts/national/daily/runs"),
        )
    )
    cache_root = Path(
        os.environ.get(
            "ITDA_GROUNDED_DAILY_CACHE_ROOT",
            str(_ROOT / "artifacts/national/daily/cache"),
        )
    )
    resources = ExitStack()
    if any(place.place_id.startswith("public:korea:") for place in catalog.places):
        from itda.pipeline.national_public_catalog import national_source_clients

        clients = resources.enter_context(
            national_source_clients(
                unquote(tour_key),
                unquote(odii_key) if odii_key else None,
                args.provider_control_root or cache_root.parent,
                resume_provider=args.resume_provider,
            )
        )
    else:
        clients = official_clients(unquote(tour_key), unquote(odii_key) if odii_key else None)
        for client in clients.values():
            resources.callback(client.close)
    cache = OfficialSourceCache(cache_root, clients=clients, live=not args.offline, ttl_days=0)
    text_provider = GroundedTextProvider(api_key=model_key, cache_version="v2")
    mood_provider = CachedDestinationMoodProvider(
        api_key=model_key, cache_directory=cache_root / "mood-models", live=not args.offline
    )

    # Bootstrap the national ACTIVE pair explicitly. A missing or retired pair
    # must never seed the scheduler from archived MVP files or overlays.
    def raw_resolver() -> None:
        return None

    evaluator = (
        (lambda _candidate: read_promotion_evidence(args.gate, args.reports)) if args.gate else None
    )
    last_processed = None
    last_gate_stamp = None
    last_wait_target = None
    try:
        while True:
            now = datetime.now(UTC)
            day = (
                args.run_date
                if args.once and args.run_date
                else (
                    now.astimezone(ZoneInfo("Asia/Seoul")).date()
                    if args.once
                    else due_run_date(now)
                )
            )
            gate_stamp = args.gate.stat().st_mtime_ns if args.gate and args.gate.is_file() else None
            reports_stamp = (
                args.reports.stat().st_mtime_ns if args.reports and args.reports.is_dir() else None
            )
            stamps = (gate_stamp, reports_stamp)
            if day is not None and (
                day != last_processed or stamps != last_gate_stamp or args.once
            ):
                try:
                    outcome = run_grounded_daily(
                        run_date=day,
                        root=root,
                        catalog=catalog,
                        store=store,
                        cache=cache,
                        text_provider=text_provider,
                        mood_provider=mood_provider,
                        raw_release_resolver=raw_resolver,
                        workers=args.workers,
                        live=not args.offline,
                        evaluator=evaluator,
                    )
                    _safe_log(
                        "grounded_daily_finished",
                        run_date=day,
                        status=outcome.status,
                        release_sha256=outcome.candidate_sha256,
                        safe_reason=outcome.reason,
                    )
                    successful = outcome.status in {"STAGED", "PROMOTED"}
                except Exception:
                    successful = False
                    _safe_log(
                        "grounded_daily_failed",
                        run_date=day,
                        status="FAILED",
                        safe_reason="GROUNDED_DAILY_FAILED",
                    )
                last_processed = day
                last_gate_stamp = stamps
                if args.once:
                    raise SystemExit(0 if successful else 1)
            target = next_run_at(datetime.now(UTC))
            if target != last_wait_target:
                _safe_log("grounded_daily_waiting", next_run_at=target)
                last_wait_target = target
            _sleep_until(target)
    finally:
        resources.close()
        engine.dispose()


def main() -> NoReturn:
    _configure_logging()
    enabled = os.environ.get("ITDA_GROUNDED_DAILY_ENABLED", "1").strip().casefold() or "1"
    if enabled in {"0", "false", "no", "off"}:
        raise RuntimeError("grounded daily refresh is disabled; no daily batch will run")
    if enabled not in {"1", "true", "yes", "on"}:
        raise RuntimeError("grounded daily refresh configuration rejected")
    _run_grounded_scheduler()


if __name__ == "__main__":
    main()
