"""Basic-Auth edge-protected daily GLM operations API."""

from __future__ import annotations

import os
from datetime import UTC, date, datetime
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from itda.api.dependencies import (
    get_daily_release_overlay_reader,
    require_same_origin_mutation,
)
from itda.contracts.mvp_daily_refresh import (
    DailyGlmExecutionDetail,
    DailyGlmExecutionHistory,
    DailyGlmOperationsOverview,
    DailyRecollectionCommandProjection,
    DailyRecollectionCommandRequest,
)
from itda.contracts.mvp_public_catalog import PublicPlaceCatalog
from itda.db.mvp_release_overlay import (
    DailyRefreshConflict,
    DailyRefreshStoreError,
    DailyReleaseOverlayReader,
)
from itda.pipeline.daily_refresh import next_run_at

router = APIRouter(prefix="/internal/operations/daily-glm/api", tags=["operations"])


@lru_cache(maxsize=1)
def _public_place_names() -> dict[str, str]:
    path = Path(
        os.environ.get(
            "ITDA_PUBLIC_PLACE_CATALOG_PATH",
            Path(__file__).resolve().parents[5]
            / "artifacts/public/catalog/public-place-catalog-v1.json",
        )
    )
    catalog = PublicPlaceCatalog.model_validate_json(path.read_bytes())
    return {row.place_id: row.name_ko for row in catalog.places}


def _unavailable(error: DailyRefreshStoreError) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="daily GLM operations unavailable",
    )


@router.get("/overview", response_model=DailyGlmOperationsOverview)
def get_overview(
    reader: Annotated[
        DailyReleaseOverlayReader,
        Depends(get_daily_release_overlay_reader),
    ],
) -> DailyGlmOperationsOverview:
    try:
        record = reader.operations_overview()
        pending = (
            reader.recollection_command(command_id=record.pending_command_id)
            if record.pending_command_id is not None
            else None
        )
    except DailyRefreshStoreError as error:
        raise _unavailable(error) from error
    return DailyGlmOperationsOverview(
        latest_execution=record.execution,
        next_run_at=next_run_at(datetime.now(UTC)),
        active_release_sha256=record.active_release_sha256,
        recollection=record.recollection,
        pending_command=pending,
    )


@router.get("/history", response_model=DailyGlmExecutionHistory)
def get_history(
    reader: Annotated[
        DailyReleaseOverlayReader,
        Depends(get_daily_release_overlay_reader),
    ],
    days: Annotated[int, Query(ge=1, le=30)] = 30,
) -> DailyGlmExecutionHistory:
    try:
        executions = reader.execution_history(days=days)
    except DailyRefreshStoreError as error:
        raise _unavailable(error) from error
    return DailyGlmExecutionHistory(days=days, executions=executions)


@router.get("/history/{run_date}", response_model=DailyGlmExecutionDetail)
def get_execution_detail(
    run_date: date,
    reader: Annotated[
        DailyReleaseOverlayReader,
        Depends(get_daily_release_overlay_reader),
    ],
    execution_sequence: Annotated[int, Query(ge=0, le=3)] = 0,
) -> DailyGlmExecutionDetail:
    try:
        record = reader.execution_detail(
            run_date=run_date,
            execution_sequence=execution_sequence,
        )
    except DailyRefreshStoreError as error:
        raise _unavailable(error) from error
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="daily GLM execution not found",
        )
    return DailyGlmExecutionDetail(
        execution=record.execution,
        collection_failures=record.collection_failures,
        attempts=record.attempts,
        excluded=(
            tuple(
                row.model_copy(
                    update={
                        "place_name_ko": _public_place_names().get(row.place_id),
                    }
                )
                for row in record.excluded
            )
            if record.excluded is not None
            else None
        ),
    )


@router.post(
    "/commands/recollect",
    response_model=DailyRecollectionCommandProjection,
    status_code=status.HTTP_202_ACCEPTED,
)
def request_recollection(
    payload: DailyRecollectionCommandRequest,
    request: Request,
    reader: Annotated[
        DailyReleaseOverlayReader,
        Depends(get_daily_release_overlay_reader),
    ],
) -> DailyRecollectionCommandProjection:
    require_same_origin_mutation(request)
    try:
        return reader.request_recollection(
            run_date=payload.run_date,
            idempotency_key=payload.idempotency_key,
        )
    except DailyRefreshConflict as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="daily GLM recollection rejected",
        ) from error
    except DailyRefreshStoreError as error:
        raise _unavailable(error) from error


@router.get(
    "/commands/{command_id}",
    response_model=DailyRecollectionCommandProjection,
)
def get_recollection_command(
    command_id: str,
    reader: Annotated[
        DailyReleaseOverlayReader,
        Depends(get_daily_release_overlay_reader),
    ],
) -> DailyRecollectionCommandProjection:
    try:
        command = reader.recollection_command(command_id=command_id)
    except DailyRefreshConflict as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="daily GLM command not found",
        ) from error
    except DailyRefreshStoreError as error:
        raise _unavailable(error) from error
    if command is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="daily GLM command not found",
        )
    return command


__all__ = ["router"]
