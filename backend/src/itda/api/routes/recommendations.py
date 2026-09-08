"""Synchronous public recommendation create and release-pinned read routes."""

from __future__ import annotations

from typing import Annotated, Any, NoReturn

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response, status

from itda.api.dependencies import (
    ProfileSessionPrincipal,
    get_optional_profile_session,
    get_recommendation_service,
    require_same_origin_mutation,
)
from itda.application.recommendations import (
    InsufficientEligibleCandidates,
    InvalidRecommendationOutput,
    NoActiveScoredRelease,
    PhotoRecommendationUnavailable,
    PreferenceProfileUnavailable,
    RecommendationService,
)
from itda.contracts.recommendation import (
    MvpRecommendationDetail,
    MvpRecommendationResultsResponse,
    OperatingInformationResponse,
    RecommendationComparisonResponse,
    RecommendationDetail,
    RecommendationErrorDetail,
    RecommendationErrorResponse,
    RecommendationPublicReason,
    RecommendationRequest,
    RecommendationResultsResponse,
    RecommendationRunCreated,
    SavedPlaceProjection,
)
from itda.db.recommendation_repositories import (
    RecommendationPinInvalid,
    RecommendationPlaceUnavailable,
    RecommendationRequestConflict,
    RecommendationRunNotFound,
)

router = APIRouter(prefix="/v1", tags=["recommendations"])
_SHA256_PATH = Annotated[str, Path(pattern=r"^[0-9a-f]{64}$")]
_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    status.HTTP_403_FORBIDDEN: {"model": RecommendationErrorResponse},
    status.HTTP_404_NOT_FOUND: {"model": RecommendationErrorResponse},
    status.HTTP_409_CONFLICT: {"model": RecommendationErrorResponse},
    status.HTTP_422_UNPROCESSABLE_CONTENT: {"model": RecommendationErrorResponse},
    status.HTTP_500_INTERNAL_SERVER_ERROR: {"model": RecommendationErrorResponse},
    status.HTTP_503_SERVICE_UNAVAILABLE: {"model": RecommendationErrorResponse},
}


def _raise_public_error(
    *,
    status_code: int,
    code: RecommendationPublicReason,
    message_ko: str,
    request_id: str | None = None,
    preference_profile_id: str | None = None,
    release_id: str | None = None,
) -> NoReturn:
    detail = RecommendationErrorDetail(
        code=code,
        message_ko=message_ko,
        request_id=request_id,
        preference_profile_id=preference_profile_id,
        release_id=release_id,
    )
    raise HTTPException(status_code=status_code, detail=detail.model_dump(mode="json"))


@router.post(
    "/recommendation-runs",
    response_model=RecommendationRunCreated,
    status_code=status.HTTP_201_CREATED,
    operation_id="createRecommendationRun",
    responses=_ERROR_RESPONSES,
)
def create_recommendation_run(
    recommendation_request: RecommendationRequest,
    http_request: Request,
    service: Annotated[RecommendationService, Depends(get_recommendation_service)],
    principal: Annotated[
        ProfileSessionPrincipal | None,
        Depends(get_optional_profile_session),
    ],
) -> RecommendationRunCreated:
    if recommendation_request.photo_job_id is not None:
        require_same_origin_mutation(http_request)
        if (
            principal is None
            or principal.profile_id != recommendation_request.preference_profile_id
        ):
            _raise_public_error(
                status_code=status.HTTP_403_FORBIDDEN,
                code=RecommendationPublicReason.INVALID_RECOMMENDATION_REQUEST,
                message_ko="현재 여행의 사진 입력을 확인하지 못했어요.",
                request_id=recommendation_request.request_id,
                preference_profile_id=recommendation_request.preference_profile_id,
            )
    try:
        return service.create_run_response(recommendation_request)
    except NoActiveScoredRelease as error:
        _raise_public_error(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            code=RecommendationPublicReason.NO_ACTIVE_SCORED_RELEASE,
            message_ko="검증된 공개 관광지 프로필이 충분히 준비된 뒤에만 추천을 보여드려요.",
            request_id=error.request_id,
            preference_profile_id=error.preference_profile_id,
        )
    except PhotoRecommendationUnavailable:
        _raise_public_error(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            code=RecommendationPublicReason.INVALID_RECOMMENDATION_REQUEST,
            message_ko="확정된 사진 취향을 확인하지 못했어요. 사진 없이 추천을 계속해 주세요.",
            request_id=recommendation_request.request_id,
            preference_profile_id=recommendation_request.preference_profile_id,
        )
    except PreferenceProfileUnavailable:
        _raise_public_error(
            status_code=status.HTTP_404_NOT_FOUND,
            code=RecommendationPublicReason.PREFERENCE_PROFILE_UNAVAILABLE,
            message_ko="현재 여행의 취향 프로필을 다시 확인해 주세요.",
            request_id=recommendation_request.request_id,
            preference_profile_id=recommendation_request.preference_profile_id,
        )
    except InsufficientEligibleCandidates:
        _raise_public_error(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            code=RecommendationPublicReason.INSUFFICIENT_ELIGIBLE_CANDIDATES,
            message_ko="현재 조건으로 검증된 추천 장소가 다섯 곳보다 적어요.",
            request_id=recommendation_request.request_id,
            preference_profile_id=recommendation_request.preference_profile_id,
        )
    except RecommendationRequestConflict:
        _raise_public_error(
            status_code=status.HTTP_409_CONFLICT,
            code=RecommendationPublicReason.RECOMMENDATION_REQUEST_CONFLICT,
            message_ko="이 요청 식별자는 이미 다른 취향 입력에 사용됐어요.",
            request_id=recommendation_request.request_id,
            preference_profile_id=recommendation_request.preference_profile_id,
        )
    except (InvalidRecommendationOutput, RecommendationPinInvalid):
        _raise_public_error(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            code=RecommendationPublicReason.INVALID_RECOMMENDATION_OUTPUT,
            message_ko="추천 결과를 안전하게 확인하지 못했어요. 잠시 후 다시 시도해 주세요.",
            request_id=recommendation_request.request_id,
            preference_profile_id=recommendation_request.preference_profile_id,
        )


@router.get(
    "/recommendation-runs/{run_id}",
    response_model=RecommendationResultsResponse | MvpRecommendationResultsResponse,
    operation_id="getRecommendationRun",
    responses=_ERROR_RESPONSES,
)
def get_recommendation_run(
    run_id: str,
    service: Annotated[RecommendationService, Depends(get_recommendation_service)],
) -> RecommendationResultsResponse | MvpRecommendationResultsResponse:
    try:
        return service.get_results(run_id)
    except RecommendationRunNotFound:
        _raise_public_error(
            status_code=status.HTTP_404_NOT_FOUND,
            code=RecommendationPublicReason.RECOMMENDATION_RUN_NOT_FOUND,
            message_ko="저장된 추천 실행을 찾을 수 없어요.",
        )
    except RecommendationPinInvalid:
        _raise_public_error(
            status_code=status.HTTP_409_CONFLICT,
            code=RecommendationPublicReason.RECOMMENDATION_PIN_INVALID,
            message_ko="저장된 추천 실행의 버전 연결을 확인할 수 없어요.",
        )


@router.get(
    "/recommendation-runs/{run_id}/places/{place_id}",
    response_model=RecommendationDetail | MvpRecommendationDetail,
    operation_id="getRecommendationPlaceDetail",
    responses=_ERROR_RESPONSES,
)
def get_recommendation_place_detail(
    run_id: str,
    place_id: str,
    service: Annotated[RecommendationService, Depends(get_recommendation_service)],
) -> RecommendationDetail | MvpRecommendationDetail:
    try:
        return service.get_detail(run_id, place_id)
    except RecommendationRunNotFound:
        _raise_public_error(
            status_code=status.HTTP_404_NOT_FOUND,
            code=RecommendationPublicReason.RECOMMENDATION_RUN_NOT_FOUND,
            message_ko="저장된 추천 실행을 찾을 수 없어요.",
        )
    except RecommendationPlaceUnavailable:
        _raise_public_error(
            status_code=status.HTTP_404_NOT_FOUND,
            code=RecommendationPublicReason.RECOMMENDATION_PLACE_UNAVAILABLE,
            message_ko="이 장소는 저장된 추천 결과에 포함되지 않았어요.",
        )
    except RecommendationPinInvalid:
        _raise_public_error(
            status_code=status.HTTP_409_CONFLICT,
            code=RecommendationPublicReason.RECOMMENDATION_PIN_INVALID,
            message_ko="저장된 추천 실행의 버전 연결을 확인할 수 없어요.",
        )


@router.get(
    "/recommendation-runs/{run_id}/operating-information",
    response_model=OperatingInformationResponse,
    operation_id="getRecommendationOperatingInformation",
    responses=_ERROR_RESPONSES,
)
def get_recommendation_operating_information(
    response: Response,
    run_id: str,
    place_id: Annotated[list[str], Query(min_length=1, max_length=5)],
    service: Annotated[RecommendationService, Depends(get_recommendation_service)],
) -> OperatingInformationResponse:
    response.headers["Cache-Control"] = "no-store"
    try:
        return service.get_operating_information(run_id, tuple(place_id))
    except RecommendationRunNotFound:
        _raise_public_error(
            status_code=status.HTTP_404_NOT_FOUND,
            code=RecommendationPublicReason.RECOMMENDATION_RUN_NOT_FOUND,
            message_ko="저장된 추천 실행을 찾을 수 없어요.",
        )
    except RecommendationPlaceUnavailable:
        _raise_public_error(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            code=RecommendationPublicReason.RECOMMENDATION_PLACE_UNAVAILABLE,
            message_ko="운영 정보를 확인할 장소를 현재 추천 결과에서 선택해 주세요.",
        )
    except RecommendationPinInvalid:
        _raise_public_error(
            status_code=status.HTTP_409_CONFLICT,
            code=RecommendationPublicReason.RECOMMENDATION_PIN_INVALID,
            message_ko="저장된 추천 실행의 버전 연결을 확인할 수 없어요.",
        )


@router.get(
    "/recommendation-runs/{run_id}/comparison",
    response_model=RecommendationComparisonResponse,
    operation_id="getRecommendationComparison",
    responses=_ERROR_RESPONSES,
)
def get_recommendation_comparison(
    run_id: str,
    place_id: Annotated[list[str], Query(min_length=2, max_length=3)],
    service: Annotated[RecommendationService, Depends(get_recommendation_service)],
) -> RecommendationComparisonResponse:
    try:
        return service.get_comparison(run_id, tuple(place_id))
    except RecommendationRunNotFound:
        _raise_public_error(
            status_code=status.HTTP_404_NOT_FOUND,
            code=RecommendationPublicReason.RECOMMENDATION_RUN_NOT_FOUND,
            message_ko="저장된 추천 실행을 찾을 수 없어요.",
        )
    except RecommendationPlaceUnavailable:
        _raise_public_error(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            code=RecommendationPublicReason.RECOMMENDATION_PLACE_UNAVAILABLE,
            message_ko="비교할 장소 두세 곳을 현재 추천 결과에서 선택해 주세요.",
        )
    except RecommendationPinInvalid:
        _raise_public_error(
            status_code=status.HTTP_409_CONFLICT,
            code=RecommendationPublicReason.RECOMMENDATION_PIN_INVALID,
            message_ko="저장된 추천 실행의 버전 연결을 확인할 수 없어요.",
        )


@router.get(
    "/saved-place-references/{release_sha256}/{place_id}",
    response_model=SavedPlaceProjection,
    operation_id="resolveSavedPlaceReference",
    responses=_ERROR_RESPONSES,
)
def resolve_saved_place_reference(
    release_sha256: _SHA256_PATH,
    place_id: str,
    service: Annotated[RecommendationService, Depends(get_recommendation_service)],
) -> SavedPlaceProjection:
    try:
        return service.resolve_saved_place_reference(release_sha256, place_id)
    except RecommendationPinInvalid:
        _raise_public_error(
            status_code=status.HTTP_409_CONFLICT,
            code=RecommendationPublicReason.RECOMMENDATION_PIN_INVALID,
            message_ko="저장된 장소의 버전 연결을 확인할 수 없어요.",
            release_id=release_sha256,
        )
