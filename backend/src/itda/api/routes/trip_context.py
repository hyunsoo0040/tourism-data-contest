"""Run-scoped tourism context; refreshing this view never reranks a saved run."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response

from itda.api.dependencies import get_recommendation_service
from itda.application.grounded_recommendations import GroundedRecommendationService
from itda.application.recommendations import InvalidRecommendationOutput, RecommendationService
from itda.contracts.grounded_recommendation import TripContextResponse
from itda.contracts.tourism_context import TourismContextResponse
from itda.db.recommendation_repositories import RecommendationPinInvalid, RecommendationRunNotFound
from itda.db.source_snapshot_repositories import SourceSnapshotInvalid

router = APIRouter(prefix="/v1", tags=["recommendations"])


@router.get(
    "/recommendation-runs/{run_id}/trip-context",
    response_model=TripContextResponse,
    operation_id="getRecommendationTripContext",
)
def get_trip_context(
    run_id: str,
    response: Response,
    service: Annotated[
        RecommendationService | GroundedRecommendationService, Depends(get_recommendation_service)
    ],
) -> TripContextResponse:
    response.headers["Cache-Control"] = "no-store"
    try:
        return service.get_trip_context(run_id)
    except RecommendationRunNotFound as error:
        raise HTTPException(
            404,
            detail={
                "code": "RECOMMENDATION_RUN_NOT_FOUND",
                "message_ko": "저장된 추천 실행을 찾을 수 없습니다.",
            },
        ) from error
    except (RecommendationPinInvalid, SourceSnapshotInvalid) as error:
        raise HTTPException(
            409,
            detail={
                "code": "RECOMMENDATION_PIN_INVALID",
                "message_ko": "저장된 관광정보의 출처 연결을 확인하지 못했습니다.",
            },
        ) from error


@router.get(
    "/recommendation-runs/{run_id}/tourism-context",
    response_model=TourismContextResponse,
    operation_id="getRecommendationTourismContext",
)
def get_tourism_context(
    run_id: str,
    response: Response,
    service: Annotated[
        RecommendationService | GroundedRecommendationService, Depends(get_recommendation_service)
    ],
) -> TourismContextResponse:
    response.headers["Cache-Control"] = "no-store"
    try:
        return service.get_tourism_context(run_id)
    except RecommendationRunNotFound as error:
        raise HTTPException(404, detail={"code": "RECOMMENDATION_RUN_NOT_FOUND"}) from error
    except (RecommendationPinInvalid, SourceSnapshotInvalid) as error:
        raise HTTPException(409, detail={"code": "RECOMMENDATION_PIN_INVALID"}) from error
    except InvalidRecommendationOutput as error:
        raise HTTPException(503, detail={"code": "TOURISM_CONTEXT_UNAVAILABLE"}) from error
