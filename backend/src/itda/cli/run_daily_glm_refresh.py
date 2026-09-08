"""Run the bounded daily PUBLIC-100 GLM refresh scheduler."""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import NoReturn

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
from itda.db.mvp_release_overlay import (
    ActiveReleaseOverlayResolver,
    DailyRefreshStore,
    DailyReleaseOverlayReader,
)
from itda.db.mvp_scored_release import resolve_active_mvp_scored_release
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
            _ROOT / "artifacts/public/catalog/public-place-catalog-v1.json",
        )
    )
    evidence_path = Path(
        os.environ.get(
            "ITDA_PUBLIC_EVIDENCE_INVENTORY_PATH",
            _ROOT / "artifacts/public/catalog/public-evidence-inventory-v1.json",
        )
    )
    relations_path = Path(
        os.environ.get(
            "ITDA_PUBLIC_PLACE_RELATIONS_PATH",
            _ROOT / "artifacts/public/catalog/public-place-relations-v1.json",
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
    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)


def main() -> NoReturn:
    _configure_logging()
    _validate_authority()
    require_live_collection_allowed(explicit_opt_in=True)
    require_live_network_allowed()
    tour_api_key = _secret("TOUR_API_SERVICE_KEY", "ITDA_TOUR_API_SERVICE_KEY_FILE")
    database_url = _required("ITDA_DAILY_GLM_REFRESH_DATABASE_URL")
    catalog, evidence, relations = _load_artifacts()
    engine = create_database_engine(database_url)
    factory = create_session_factory(engine)
    store = DailyRefreshStore(factory)
    reader = DailyReleaseOverlayReader(factory)
    active_resolver = ActiveReleaseOverlayResolver(
        overlay_reader=reader,
        bundled_resolver=resolve_active_mvp_scored_release,
    )
    last_wait_target: datetime | None = None
    while True:
        if _run_recollection_command(
            store=store,
            reader=reader,
            active_resolver=active_resolver,
            catalog=catalog,
            evidence=evidence,
            relations=relations,
            tour_api_key=tour_api_key,
        ):
            continue
        now = datetime.now(UTC)
        run_date = due_run_date(now)
        if run_date is not None:
            _run_one(
                run_date=run_date,
                store=store,
                reader=reader,
                active_resolver=active_resolver,
                catalog=catalog,
                evidence=evidence,
                relations=relations,
                tour_api_key=tour_api_key,
            )
            store.purge(cutoff=run_date - timedelta(days=90))
        target = next_run_at(datetime.now(UTC))
        if target != last_wait_target:
            _safe_log("daily_glm_refresh_waiting", next_run_at=target)
            last_wait_target = target
        _sleep_until(target)


if __name__ == "__main__":
    main()
