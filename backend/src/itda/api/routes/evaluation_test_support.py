"""Synthetic-only Phase 3 E2E controls excluded from the normal application."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status

from itda.api.dependencies import (
    Phase3Principal,
    get_evaluation_repository,
    get_phase3_principal,
    revoke_phase3_capability,
)
from itda.api.routes.evaluation import (
    ProfileReleaseBuildDraftCreateRequest,
    _E2E_SOURCE_ASSIGNMENT_ID,
    _profile_release_authority_service,
    _ProfileReleaseAuthorityService,
    _read_bounded_regular_file,
)
from itda.contracts.base import Sha256, StrictContract
from itda.contracts.profile_release import ProfileReleaseBuildDraftReference
from itda.db.evaluation_repositories import EvaluationRepository
from itda.domain.canonical import canonical_json_bytes

router = APIRouter(
    prefix="/internal/test-support/phase3",
    tags=["phase3-e2e-test-support"],
)
_FIXTURE_PATH = (
    Path(__file__).resolve().parents[5] / "fixtures" / "synthetic" / "phase3" / "e2e-runtime.json"
)
_ALLOWED_FIXTURE_FIELDS = {
    "schema_version",
    "synthetic_only",
    "assignment",
    "rubric_reference",
    "sources",
    "evidence_items",
    "release",
}
_BUILD_INPUT_ENVIRONMENT = "ITDA_E2E_PHASE3_RELEASE_BUILD_INPUT"
_BUILD_INPUT_SHA256_ENVIRONMENT = "ITDA_E2E_PHASE3_RELEASE_BUILD_INPUT_SHA256"
_ATTEMPT_PATTERN = r"^r[0-9]+-e[0-9]+-w[0-9]+$"


class _ReleaseDraftPreparation(StrictContract):
    reviewed_evidence_manifest_sha256: Sha256


@lru_cache(maxsize=1)
def _fixture_projection() -> dict[str, object]:
    payload = json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("synthetic_only") is not True:
        raise RuntimeError("Phase 3 synthetic fixture is invalid")
    if set(payload) != _ALLOWED_FIXTURE_FIELDS:
        raise RuntimeError("Phase 3 synthetic fixture fields are invalid")
    return {field: payload[field] for field in sorted(_ALLOWED_FIXTURE_FIELDS)}


@router.get("/fixture")
def get_synthetic_fixture(
    _principal: Annotated[Phase3Principal, Depends(get_phase3_principal)],
    attempt: Annotated[
        str | None,
        Query(pattern=_ATTEMPT_PATTERN, max_length=32),
    ] = None,
) -> dict[str, object]:
    """Return only the fixed membership-free synthetic projection."""

    projection = _fixture_projection()
    if attempt is None:
        return projection
    assignment = projection.get("assignment")
    if not isinstance(assignment, dict) or assignment.get("assignment_id") != (
        _E2E_SOURCE_ASSIGNMENT_ID
    ):
        raise RuntimeError("Phase 3 synthetic fixture assignment is invalid")
    return projection | {
        "assignment": assignment
        | {"assignment_id": f"{_E2E_SOURCE_ASSIGNMENT_ID}-{attempt}"}
    }


@router.post("/revoke-self", status_code=status.HTTP_204_NO_CONTENT)
def revoke_requesting_binding(
    capability: Annotated[
        str | None,
        Header(alias="X-ITDA-Phase3-Capability", include_in_schema=False),
    ] = None,
) -> Response:
    """Revoke the caller's server binding without exposing its digest or role."""

    revoke_phase3_capability(capability or "")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/profile-release-build-draft",
    response_model=ProfileReleaseBuildDraftReference,
    status_code=status.HTTP_201_CREATED,
)
def prepare_profile_release_build_draft(
    request: _ReleaseDraftPreparation,
    principal: Annotated[Phase3Principal, Depends(get_phase3_principal)],
    repository: Annotated[EvaluationRepository, Depends(get_evaluation_repository)],
    authority: Annotated[
        _ProfileReleaseAuthorityService,
        Depends(_profile_release_authority_service),
    ],
) -> ProfileReleaseBuildDraftReference:
    """Convert one persisted routed review into an opaque authoritative build draft."""

    if principal.role != "builder":
        raise HTTPException(status_code=403, detail="phase 3 builder capability required")
    reviewed = repository.get_reviewed_evidence_manifest(
        request.reviewed_evidence_manifest_sha256
    )
    candidate_sha256 = os.environ.get("ITDA_PHASE3_CANDIDATE_MANIFEST_SHA256")
    if (
        reviewed is None
        or candidate_sha256 is None
        or not hmac.compare_digest(reviewed.candidate_manifest_sha256, candidate_sha256)
    ):
        raise HTTPException(status_code=409, detail="reviewed evidence state is incomplete")
    configured_path = os.environ.get(_BUILD_INPUT_ENVIRONMENT)
    configured_sha256 = os.environ.get(_BUILD_INPUT_SHA256_ENVIRONMENT)
    if configured_path is None or configured_sha256 is None:
        raise HTTPException(status_code=503, detail="release build authority is unavailable")
    try:
        raw = _read_bounded_regular_file(Path(configured_path))
        if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), configured_sha256):
            raise ValueError("release build input digest drifted")
        payload = json.loads(raw)
        if not isinstance(payload, dict) or raw != canonical_json_bytes(payload):
            raise ValueError("release build input is not canonical")
        reconciliation_nonce = secrets.token_hex(32)
        draft_ref = secrets.token_urlsafe(32)
        draft_request = ProfileReleaseBuildDraftCreateRequest.model_validate(
            payload
            | {
                "reconciliation_nonce": reconciliation_nonce,
                "draft_ref": draft_ref,
            }
        )
        authority_resolution = authority.resolve_request(
            draft_request,
            principal=principal,
            repository=repository,
        )
        return repository.create_profile_release_build_draft(
            authority_resolution.candidate,
            authenticated_principal=principal.actor_id,
            reconciliation_nonce=reconciliation_nonce,
            draft_ref=draft_ref,
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="release build authority is unavailable",
        ) from None
