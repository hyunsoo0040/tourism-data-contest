"""IT-DA FastAPI application composition."""

import os

from fastapi import FastAPI, Request, Response
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from itda.api.dependencies import validate_profile_session_startup
from itda.api.routes.evaluation import router as evaluation_router
from itda.api.routes.journey import router as journey_router
from itda.api.routes.operations import router as operations_router
from itda.api.routes.photo import (
    PhotoErrorDetail,
    PhotoErrorResponse,
    get_photo_lifecycle,
)
from itda.api.routes.photo import router as photo_router
from itda.api.routes.recommendations import router as recommendations_router
from itda.contracts.recommendation import (
    RecommendationErrorDetail,
    RecommendationErrorResponse,
    RecommendationPublicReason,
)

_PROFILE_RELEASE_PATH_PREFIX = "/internal/evaluation/profile-releases/"
_MUTATION_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_RECOMMENDATION_CREATE_PATH = "/v1/recommendation-runs"
_PHOTO_MUTATION_PATH_PREFIX = "/v1/photo-jobs"


def _is_profile_release_mutation(request: Request) -> bool:
    """Fail closed for validation errors on the protected mutation namespace."""

    return request.method.upper() in _MUTATION_METHODS and request.url.path.startswith(
        _PROFILE_RELEASE_PATH_PREFIX
    )


def _is_photo_mutation(request: Request) -> bool:
    """Bound validation errors on the photo mutation namespace."""

    return request.method.upper() in _MUTATION_METHODS and request.url.path.startswith(
        _PHOTO_MUTATION_PATH_PREFIX
    )


def create_app() -> FastAPI:
    async def lifespan(_application: FastAPI):  # type: ignore[no-untyped-def]
        if os.environ.get("ITDA_DATABASE_URL"):
            validate_profile_session_startup()
        if os.environ.get("ITDA_PHOTO_SERVICE_DATABASE_URL"):
            get_photo_lifecycle().reconcile_on_startup()
        yield

    application = FastAPI(
        title="IT-DA API",
        version="1.0.0",
        description="Versioned current-trip expectation profile API",
        lifespan=lifespan,
    )

    @application.exception_handler(RequestValidationError)
    async def redact_sensitive_request_validation(
        request: Request,
        error: RequestValidationError,
    ) -> Response:
        if _is_profile_release_mutation(request):
            return JSONResponse(
                status_code=422,
                content={"detail": "profile release request is structurally invalid"},
            )
        if request.method.upper() == "POST" and request.url.path == _RECOMMENDATION_CREATE_PATH:
            recommendation_bounded = RecommendationErrorResponse(
                detail=RecommendationErrorDetail(
                    code=RecommendationPublicReason.INVALID_RECOMMENDATION_REQUEST,
                    message_ko="추천 요청 형식을 확인해 주세요.",
                )
            )
            return JSONResponse(
                status_code=422,
                content=recommendation_bounded.model_dump(mode="json"),
            )
        if _is_photo_mutation(request):
            photo_bounded = PhotoErrorResponse(
                detail=PhotoErrorDetail(
                    code="PHOTO_REQUEST_INVALID",
                    message_ko="사진 요청 형식을 확인해 주세요.",
                )
            )
            return JSONResponse(
                status_code=422,
                content=photo_bounded.model_dump(mode="json"),
            )
        return await request_validation_exception_handler(request, error)

    application.include_router(journey_router)
    application.include_router(recommendations_router)
    application.include_router(photo_router)
    application.include_router(evaluation_router)
    application.include_router(operations_router)
    if os.environ.get("ITDA_E2E_PHASE3_TEST_SUPPORT") == "1":
        from itda.api.routes.evaluation_test_support import (
            router as evaluation_test_support_router,
        )

        application.include_router(evaluation_test_support_router)
    return application


app = create_app()
