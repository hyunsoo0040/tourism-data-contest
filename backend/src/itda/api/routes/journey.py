"""Versioned questionnaire and preference-profile routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response, status
from pydantic import Field

from itda.api.dependencies import (
    PROFILE_SESSION_COOKIE_NAME,
    ProfileSessionPrincipal,
    create_profile_and_issue_session,
    enforce_profile_create_rate,
    get_optional_profile_session,
    get_preference_service,
    get_profile_session,
    require_same_origin_mutation,
    rotate_profile_session,
)
from itda.application.preferences import PreferenceService
from itda.contracts.base import StrictContract
from itda.contracts.preference import PreferenceProfile, QuestionnaireSubmission
from itda.contracts.questionnaire_v2 import (
    QUESTIONNAIRE_DEFINITION_V2,
    QuestionnaireDefinitionV2,
)

router = APIRouter(prefix="/v1", tags=["journey"])


class ErrorResponse(StrictContract):
    """Bounded JSON error body shared by declared API failure responses."""

    detail: Annotated[str, Field(strict=True, min_length=1, max_length=500)]


@router.get(
    "/questionnaires/current",
    response_model=QuestionnaireDefinitionV2,
    operation_id="getCurrentQuestionnaire",
)
def get_current_questionnaire() -> QuestionnaireDefinitionV2:
    return QUESTIONNAIRE_DEFINITION_V2


@router.post(
    "/preference-profiles",
    response_model=PreferenceProfile,
    status_code=status.HTTP_201_CREATED,
    operation_id="createPreferenceProfile",
    responses={
        status.HTTP_409_CONFLICT: {
            "model": ErrorResponse,
            "description": "The request ID is already bound to different preference input",
        }
    },
)
def create_preference_profile(
    submission: QuestionnaireSubmission,
    request: Request,
    response: Response,
    service: Annotated[PreferenceService, Depends(get_preference_service)],
    principal: Annotated[
        ProfileSessionPrincipal | None,
        Depends(get_optional_profile_session),
    ],
) -> PreferenceProfile:
    require_same_origin_mutation(request)
    enforce_profile_create_rate(request)
    existing = service.get_profile_by_request_id(submission.request_id)
    if existing is not None and (
        existing.trip_conditions != submission.trip_conditions
        or existing.answers != submission.answers
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="request_id already belongs to different preference input",
        )
    if existing is not None:
        if principal is None or principal.profile_id != existing.profile_id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="valid current profile session required",
            )
        issued = rotate_profile_session(request=request, principal=principal)
        if issued is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="valid current profile session required",
            )
        cookie, max_age, secure = issued
        response.set_cookie(
            PROFILE_SESSION_COOKIE_NAME,
            cookie,
            max_age=max_age,
            httponly=True,
            secure=secure,
            samesite="strict",
            path="/",
        )
        return existing
    profile = service.build_profile(submission)
    issued = create_profile_and_issue_session(
        request=request,
        profile=profile,
        predecessor=principal,
    )
    if issued is None:
        winner = service.get_profile_by_request_id(submission.request_id)
        if winner is not None and (
            winner.trip_conditions != submission.trip_conditions
            or winner.answers != submission.answers
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="request_id already belongs to different preference input",
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="valid current profile session required",
        )
    cookie, max_age, secure = issued
    response.set_cookie(
        PROFILE_SESSION_COOKIE_NAME,
        cookie,
        max_age=max_age,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/",
    )
    return profile


@router.get(
    "/preference-profiles/{profile_id}",
    response_model=PreferenceProfile,
    operation_id="getPreferenceProfile",
    responses={
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "The preference profile was not found",
        }
    },
)
def get_preference_profile(
    profile_id: Annotated[str, Path(min_length=1, max_length=160)],
    service: Annotated[PreferenceService, Depends(get_preference_service)],
    principal: Annotated[ProfileSessionPrincipal, Depends(get_profile_session)],
) -> PreferenceProfile:
    if principal.profile_id != profile_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="current profile session does not own this profile",
        )
    profile = service.get_profile(profile_id)
    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="preference profile not found",
        )
    return profile
