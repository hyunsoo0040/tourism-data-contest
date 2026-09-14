"""Additive owned appearance review; historical trait routes retain their schema."""

from typing import Annotated

from fastapi import APIRouter, Depends, Path, Request

from itda.api.dependencies import (
    ProfileSessionPrincipal,
    get_profile_session,
    require_same_origin_mutation,
)
from itda.api.routes.photo import (
    _PHOTO_ERROR_RESPONSES,
    PhotoLifecycleGateway,
    _map_lifecycle_failure,
    get_photo_lifecycle,
)
from itda.contracts.visual_mood import (
    ConfirmedMoodProjection,
    PhotoMoodConfirmRequest,
    PhotoMoodReview,
)
from itda.photo.contracts import PHOTO_JOB_ID_PATTERN
from itda.photo.jobs import PhotoJobError

router = APIRouter(prefix="/v1", tags=["photo-mood"])


@router.get(
    "/photo-jobs/{job_id}/moods",
    response_model=PhotoMoodReview,
    operation_id="getPhotoJobMoods",
    responses=_PHOTO_ERROR_RESPONSES,
)
def get_photo_moods(
    job_id: Annotated[str, Path(pattern=PHOTO_JOB_ID_PATTERN)],
    principal: Annotated[ProfileSessionPrincipal, Depends(get_profile_session)],
    lifecycle: Annotated[PhotoLifecycleGateway, Depends(get_photo_lifecycle)],
) -> PhotoMoodReview:
    try:
        lifecycle._acquire("poll", principal.profile_id)
        state = lifecycle._read_owned(job_id=job_id, profile_id=principal.profile_id)
        if state["state"] != "succeeded":
            raise PhotoJobError("photo review is not available")
        return lifecycle.mood_service.review(job_id=job_id, profile_id=principal.profile_id)
    except Exception as error:
        _map_lifecycle_failure(error, job_id=job_id, preference_profile_id=principal.profile_id)


@router.post(
    "/photo-jobs/{job_id}/moods/confirm",
    response_model=ConfirmedMoodProjection,
    operation_id="confirmPhotoJobMoods",
    responses=_PHOTO_ERROR_RESPONSES,
)
def confirm_photo_moods(
    job_id: Annotated[str, Path(pattern=PHOTO_JOB_ID_PATTERN)],
    payload: PhotoMoodConfirmRequest,
    request: Request,
    principal: Annotated[ProfileSessionPrincipal, Depends(get_profile_session)],
    lifecycle: Annotated[PhotoLifecycleGateway, Depends(get_photo_lifecycle)],
) -> ConfirmedMoodProjection:
    require_same_origin_mutation(request)
    try:
        lifecycle._acquire("poll", principal.profile_id)
        state = lifecycle._read_owned(job_id=job_id, profile_id=principal.profile_id)
        if state["state"] != "succeeded":
            raise PhotoJobError("photo confirmation is not available")
        return lifecycle.mood_service.confirm(
            job_id=job_id,
            profile_id=principal.profile_id,
            choices=payload.choices,
            draft_sha256=payload.draft_sha256,
        )
    except Exception as error:
        _map_lifecycle_failure(error, job_id=job_id, preference_profile_id=principal.profile_id)
