"""New experience journey API; legacy profile and run routes retain their contracts."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, File, Header, HTTPException, Request, UploadFile
from sqlalchemy.exc import SQLAlchemyError

from itda.api.dependencies import enforce_profile_create_rate, require_same_origin_mutation
from itda.authenticity.api_contracts import (
    Comparison,
    CreateRun,
    Definition,
    Detail,
    FeedbackCreated,
    FeedbackRequest,
    PhotoConfirmation,
    RunResult,
    SavedItem,
    SaveRequest,
    ServiceInfo,
    SessionCreated,
)
from itda.authenticity.display_photos import load_display_photos
from itda.authenticity.intent import (
    QUESTIONNAIRE,
    QUESTIONNAIRE_SHA256,
    Intent,
    IntentSubmission,
    ScenarioSubmission,
)
from itda.authenticity.photo import PhotoReview, analyze_uploads, confirm
from itda.authenticity.repository import OwnershipError, Repository, RequestConflict
from itda.authenticity.service import Service
from itda.db.session import create_database_engine
from itda.photo.provider.mood import GlmMoodProvider, MoodProvider

router = APIRouter(prefix="/v1/authenticity", tags=["authenticity"])


@lru_cache(maxsize=1)
def get_service() -> Service:
    # Existing Portainer stacks export the runtime DSN inside their command.
    # An explicit authenticity DSN (including an empty one) keeps precedence.
    dsn = os.environ.get("ITDA_AUTHENTICITY_DATABASE_URL", os.environ.get("ITDA_DATABASE_URL", ""))
    if not dsn:
        raise HTTPException(503, "새 경험 자료를 준비하고 있습니다.")
    return Service(
        Repository(create_database_engine(dsn)),
        allow_development=os.environ.get("ITDA_AUTHENTICITY_ALLOW_DEVELOPMENT") == "1",
        photo_enabled=os.environ.get("ITDA_AUTHENTICITY_PHOTO_ENABLED") == "1",
        display_photos=load_display_photos(
            Path(os.environ["ITDA_AUTHENTICITY_RELEASE_DIR"])
            if os.environ.get("ITDA_AUTHENTICITY_RELEASE_DIR")
            else None
        ),
        noncommercial_photos=os.environ.get("ITDA_DISPLAY_PHOTO_NONCOMMERCIAL") == "1",
    )


def principal(
    service: Annotated[Service, Depends(get_service)],
    authorization: Annotated[str | None, Header()] = None,
) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "여행 세션을 다시 시작해 주세요.")
    try:
        return service.repository.session(authorization[7:])
    except OwnershipError:
        raise HTTPException(401, "여행 세션이 만료되었습니다.") from None


def provider() -> MoodProvider:
    from itda.api.routes.photo import _photo_provider_api_key

    if os.environ.get("ITDA_AUTHENTICITY_PHOTO_ENABLED") != "1":
        raise HTTPException(503, "사진 분석을 사용할 수 없습니다.")
    key = _photo_provider_api_key()
    if not key:
        raise HTTPException(503, "사진 분석을 사용할 수 없습니다.")
    return GlmMoodProvider(api_key=key, explicit_opt_in=True, session_limit=5)


def guarded_error(error: Exception) -> HTTPException:
    if isinstance(error, OwnershipError):
        return HTTPException(404, "이 세션에서 자료를 찾을 수 없습니다.")
    if isinstance(error, RequestConflict):
        return HTTPException(409, "요청 내용이 변경되었습니다. 다시 시도해 주세요.")
    if isinstance(error, SQLAlchemyError):
        return HTTPException(503, "저장소에 연결하지 못했습니다. 잠시 후 다시 시도해 주세요.")
    if str(error) == "NO_ACTIVE_AUTHENTICITY_RELEASE":
        return HTTPException(503, "새 경험 자료를 준비하고 있습니다.")
    return HTTPException(422, "입력과 연결된 근거를 확인해 주세요.")


@router.get("/definition", response_model=Definition, operation_id="getAuthenticityDefinition")
def definition() -> Definition:
    return Definition.model_validate(QUESTIONNAIRE | {"questionnaire_sha256": QUESTIONNAIRE_SHA256})


@router.get("/info", response_model=ServiceInfo, operation_id="getAuthenticityInfo")
def info(service: Annotated[Service, Depends(get_service)]) -> ServiceInfo:
    try:
        return service.info()
    except (ValueError, SQLAlchemyError) as error:
        raise guarded_error(error) from None


@router.post("/sessions", response_model=SessionCreated, operation_id="createAuthenticitySession")
def create_session(
    request: Request, service: Annotated[Service, Depends(get_service)]
) -> SessionCreated:
    require_same_origin_mutation(request)
    enforce_profile_create_rate(request)
    try:
        return SessionCreated.model_validate(service.repository.create_session())
    except SQLAlchemyError as error:
        raise guarded_error(error) from None


@router.delete("/session", operation_id="deleteAuthenticitySession")
def delete_session(
    request: Request,
    sid: Annotated[str, Depends(principal)],
    service: Annotated[Service, Depends(get_service)],
) -> dict[str, bool]:
    require_same_origin_mutation(request)
    service.repository.delete_session(sid)
    return {"deleted": True}


@router.post("/profiles", response_model=Intent, operation_id="createAuthenticityIntent")
def create_profile(
    submission: IntentSubmission,
    request: Request,
    sid: Annotated[str, Depends(principal)],
    service: Annotated[Service, Depends(get_service)],
) -> Intent:
    require_same_origin_mutation(request)
    try:
        return service.profile(sid, submission)
    except (ValueError, SQLAlchemyError) as error:
        raise guarded_error(error) from None


@router.post(
    "/scenario-profiles", response_model=Intent, operation_id="createScenarioAuthenticityIntent"
)
def create_scenario_profile(
    body: ScenarioSubmission,
    request: Request,
    sid: Annotated[str, Depends(principal)],
    service: Annotated[Service, Depends(get_service)],
) -> Intent:
    require_same_origin_mutation(request)
    enforce_profile_create_rate(request)
    try:
        return service.profile(sid, body)
    except (ValueError, SQLAlchemyError) as error:
        raise guarded_error(error) from None


@router.get("/profiles/{profile_id}", response_model=Intent, operation_id="getAuthenticityIntent")
def get_profile(
    profile_id: str,
    sid: Annotated[str, Depends(principal)],
    service: Annotated[Service, Depends(get_service)],
) -> Intent:
    try:
        return service.repository.get_intent(sid, profile_id)
    except (ValueError, SQLAlchemyError) as error:
        raise guarded_error(error) from None


@router.post("/runs", response_model=RunResult, operation_id="createAuthenticityRun")
def create_run(
    body: CreateRun,
    request: Request,
    sid: Annotated[str, Depends(principal)],
    service: Annotated[Service, Depends(get_service)],
) -> RunResult:
    require_same_origin_mutation(request)
    try:
        return service.create_run(sid, body.profile_id, body.request_id)
    except (ValueError, SQLAlchemyError) as error:
        raise guarded_error(error) from None


@router.get("/runs/{run_id}", response_model=RunResult, operation_id="getAuthenticityRun")
def get_run(
    run_id: str,
    sid: Annotated[str, Depends(principal)],
    service: Annotated[Service, Depends(get_service)],
) -> RunResult:
    try:
        return RunResult.model_validate(service.run(sid, run_id))
    except (ValueError, SQLAlchemyError) as error:
        raise guarded_error(error) from None


@router.get(
    "/runs/{run_id}/places/{place_id}", response_model=Detail, operation_id="getAuthenticityDetail"
)
def detail(
    run_id: str,
    place_id: str,
    sid: Annotated[str, Depends(principal)],
    service: Annotated[Service, Depends(get_service)],
) -> Detail:
    try:
        return service.detail(sid, run_id, place_id)
    except (ValueError, SQLAlchemyError) as error:
        raise guarded_error(error) from None


@router.get(
    "/runs/{run_id}/compare", response_model=Comparison, operation_id="compareAuthenticityPlaces"
)
def compare(
    run_id: str,
    place_ids: str,
    sid: Annotated[str, Depends(principal)],
    service: Annotated[Service, Depends(get_service)],
) -> Comparison:
    ids = tuple(dict.fromkeys(place_ids.split(",")))
    if not 1 <= len(ids) <= 3:
        raise HTTPException(422, "최대 세 장소를 비교할 수 있습니다.")
    try:
        return Comparison(places=tuple(service.detail(sid, run_id, pid) for pid in ids))
    except (ValueError, SQLAlchemyError) as error:
        raise guarded_error(error) from None


@router.put("/runs/{run_id}/places/{place_id}/saved", operation_id="saveAuthenticityPlace")
def save(
    run_id: str,
    place_id: str,
    body: SaveRequest,
    request: Request,
    sid: Annotated[str, Depends(principal)],
    service: Annotated[Service, Depends(get_service)],
) -> dict[str, bool]:
    require_same_origin_mutation(request)
    try:
        service.repository.save(sid, run_id, place_id, saved=body.saved)
    except (ValueError, SQLAlchemyError) as error:
        raise guarded_error(error) from None
    return {"saved": body.saved}


@router.get("/saved", response_model=list[SavedItem], operation_id="getAuthenticitySaved")
def saved(
    sid: Annotated[str, Depends(principal)], service: Annotated[Service, Depends(get_service)]
) -> list[SavedItem]:
    return [SavedItem.model_validate(row) for row in service.repository.saved(sid)]


@router.post(
    "/runs/{run_id}/places/{place_id}/feedback",
    response_model=FeedbackCreated,
    operation_id="recordAuthenticityFeedback",
)
def feedback(
    run_id: str,
    place_id: str,
    body: FeedbackRequest,
    request: Request,
    sid: Annotated[str, Depends(principal)],
    service: Annotated[Service, Depends(get_service)],
) -> FeedbackCreated:
    require_same_origin_mutation(request)
    if not body.visited and any(v is not None for v in body.expectations_met.values()):
        raise HTTPException(422, "방문하지 않은 장소의 경험 점수는 남길 수 없습니다.")
    try:
        identifier = service.repository.feedback(
            sid, run_id, place_id, body.model_dump(mode="json")
        )
    except (ValueError, SQLAlchemyError) as error:
        raise guarded_error(error) from None
    return FeedbackCreated(feedback_id=identifier)


@router.post("/photos", response_model=PhotoReview, operation_id="analyzeAuthenticityPhoto")
async def photos(
    request: Request,
    files: Annotated[list[UploadFile], File()],
    sid: Annotated[str, Depends(principal)],
    service: Annotated[Service, Depends(get_service)],
    mood_provider: Annotated[MoodProvider, Depends(provider)],
) -> PhotoReview:
    from starlette.concurrency import run_in_threadpool

    require_same_origin_mutation(request)
    raw = []
    try:
        if not 1 <= len(files) <= 3:
            raise ValueError("PHOTO_COUNT_LIMIT")
        for file in files:
            data = await file.read(10 * 1024 * 1024 + 1)
            raw.append(bytearray(data))
            del data
        review = await run_in_threadpool(analyze_uploads, raw, mood_provider)
        service.repository.put_photo(sid, review)
        return review
    except Exception:
        raise HTTPException(
            422, "사진을 분석하지 못했습니다. 다른 사진을 선택하거나 건너뛰어 주세요."
        ) from None
    finally:
        for buffer in raw:
            buffer[:] = b"\0" * len(buffer)
        for file in files:
            await file.close()


@router.post(
    "/photos/{photo_id}/confirm",
    response_model=PhotoReview,
    operation_id="confirmAuthenticityPhoto",
)
def confirm_photo(
    photo_id: str,
    body: PhotoConfirmation,
    request: Request,
    sid: Annotated[str, Depends(principal)],
    service: Annotated[Service, Depends(get_service)],
) -> PhotoReview:
    require_same_origin_mutation(request)
    try:
        review = PhotoReview.model_validate(service.repository.get_photo(sid, photo_id))
        result = confirm(review, body.candidate_ids)
        service.repository.put_photo(sid, result)
        return result
    except (ValueError, SQLAlchemyError) as error:
        raise guarded_error(error) from None


@router.delete(
    "/photos/{photo_id}", response_model=PhotoReview, operation_id="deleteAuthenticityPhoto"
)
def delete_photo(
    photo_id: str,
    request: Request,
    sid: Annotated[str, Depends(principal)],
    service: Annotated[Service, Depends(get_service)],
) -> PhotoReview:
    require_same_origin_mutation(request)
    try:
        old = PhotoReview.model_validate(service.repository.get_photo(sid, photo_id))
        result = PhotoReview(
            photo_id=old.photo_id, state="DELETED", batches=(), created_at=old.created_at
        )
        service.repository.put_photo(sid, result)
        return result
    except (ValueError, SQLAlchemyError) as error:
        raise guarded_error(error) from None
