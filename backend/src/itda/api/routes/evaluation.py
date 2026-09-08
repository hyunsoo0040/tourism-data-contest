"""Internal Phase 3 evaluator routes with server-bound actor authority."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal, cast

from fastapi import APIRouter, Body, Depends, HTTPException, status
from pydantic import Field, StrictBool, ValidationError, model_validator
from sqlalchemy.exc import DBAPIError, IntegrityError

from itda.api.dependencies import (
    Phase3Principal,
    get_daily_release_overlay_reader,
    get_evaluation_repository,
    get_phase3_principal,
)
from itda.cli.freeze_labels import LabelFreezeReceipt, publish_label_freeze
from itda.contracts.base import Sha256, StrictContract
from itda.contracts.labeling import (
    AcceptedRevisionSelection,
    AdjudicatedAttributeValue,
    AdjudicatedLabelExport,
    AdjudicationOfficialSource,
    AdjudicationProjection,
    AdjudicationSourceManifest,
    AttributeJudgment,
    EvidenceLane,
    LabelExportBlocked,
    RawLabelRevision,
    ReviewTrigger,
    ReviewTriggerResolution,
)
from itda.contracts.mvp_daily_refresh import DailyRefreshStatusProjection
from itda.contracts.place_profile import SubattributeId
from itda.contracts.profile_release import (
    ProfileReleaseActivePointerProjection,
    ProfileReleaseBuildDraftReference,
    ProfileReleaseBuildOutcome,
    ProfileReleaseBuildUnavailableError,
    ProfileReleaseCandidate,
    ProfileReleaseDraftCleanupUnknownError,
    ProfileReleaseReplayError,
    ProfileReleaseRetryableAbortError,
    ProfileReleaseSessionPinProjection,
    ProfileReleaseState,
    ProfileReleaseStateProjection,
    ProfileReleaseTransitionOutcome,
    ProfileReleaseUnknownOutcomeError,
)
from itda.contracts.profile_release_authority import (
    ProfileReleaseAuthorityError,
    ProfileReleaseAuthorityPaths,
    ProfileReleaseAuthorityRequest,
    ProfileReleaseBuildAuthorityResolution,
    parse_profile_release_authority_registry_id,
    resolve_authoritative_profile_release_build_authority,
)
from itda.contracts.text_evidence import (
    AcceptedEvidenceReviewHead,
    EvidenceRelevanceDecision,
    EvidenceReviewChain,
    EvidenceReviewQueue,
    EvidenceReviewReceipt,
    EvidenceReviewRevision,
    ReviewedEvidenceManifest,
)
from itda.contracts.text_evidence import (
    EvidenceLane as TextEvidenceLane,
)
from itda.db.evaluation_repositories import (
    AcceptedHeadReceipt,
    EvaluationRepository,
    LabelSubmissionStatus,
    StoredLabelRevision,
)
from itda.db.mvp_release_overlay import DailyRefreshStoreError, DailyReleaseOverlayReader
from itda.pipeline.daily_refresh import next_run_at

router = APIRouter(prefix="/internal/evaluation", tags=["internal-evaluation"])
_CLIENT_IDENTITY_FIELDS = frozenset(
    {"actor_id", "role", "evaluator_principal", "evaluator_pseudonym"}
)


class AcceptedHeadRequest(StrictContract):
    reason: Annotated[str, Field(strict=True, min_length=1, max_length=300)]
    selected_at: datetime | None = None
    expected_chain_sha256: Sha256


class ReviewResolutionRequest(StrictContract):
    review_trigger_sha256: Sha256
    reason: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    resolved_at: datetime | None = None


class AttributeAdjudicationRequest(StrictContract):
    attribute_id: SubattributeId
    exact_median: Annotated[str, Field(strict=True, pattern=r"^[0-4]\.5$")]
    adjudicated_value: Annotated[int, Field(strict=True, ge=0, le=4)]
    reason: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    adjudicated_at: datetime | None = None


class AggregateRequest(StrictContract):
    adjudications: tuple[AttributeAdjudicationRequest, ...] = ()


class LabelFreezeRequest(StrictContract):
    export_sha256: Sha256
    rubric_sha256: Sha256
    source_root_sha256: Sha256
    dev_lineage_sha256: Sha256


class EvidenceReviewRequest(StrictContract):
    candidate_manifest_sha256: Sha256
    candidate_sha256: Sha256
    lane: TextEvidenceLane
    decision: EvidenceRelevanceDecision
    reason: Annotated[str, Field(strict=True, min_length=1, max_length=300)]
    reviewed_at: datetime | None = None


class EvidenceReviewCorrectionRequest(EvidenceReviewRequest):
    correction_reason: Annotated[str, Field(strict=True, min_length=1, max_length=300)]


class EvidenceReviewHeadRequest(StrictContract):
    candidate_manifest_sha256: Sha256
    candidate_id: Sha256
    candidate_sha256: Sha256
    lane: TextEvidenceLane
    expected_chain_sha256: Sha256
    selection_reason: Annotated[str, Field(strict=True, min_length=1, max_length=300)]
    selected_at: datetime | None = None


class ReviewedEvidenceFinalizeRequest(StrictContract):
    candidate_manifest_sha256: Sha256
    finalized_at: datetime | None = None


class ProfileReleaseBuildCohortMemberRequest(StrictContract):
    """Informational client projection; eligibility is always server-derived."""

    place_ref: Annotated[str, Field(strict=True, min_length=1, max_length=200)]
    label_ready: StrictBool
    rights_ready: StrictBool
    evidence_ready: StrictBool
    description_lane: Literal["READY", "MISSING"]
    odii_lane: Literal["READY", "MISSING"]
    profile_sha256: Sha256
    label_export_sha256: Sha256
    candidate_manifest_sha256: Sha256
    reviewed_evidence_manifest_sha256: Sha256
    accepted_review_set_sha256: Sha256
    rights_sha256: Sha256
    source_sha256: Sha256


class ProfileReleaseBuildRequest(StrictContract):
    schema_version: Literal["itda.profile-release-candidate.v1"] = (
        "itda.profile-release-candidate.v1"
    )
    release_id: Annotated[
        str,
        Field(strict=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"),
    ]
    canonical_lineage_sha256: Sha256
    dev_lineage_sha256: Sha256
    profile_schema_sha256: Sha256
    label_freeze_sha256: Sha256
    candidate_run_sha256: Sha256
    reviewed_manifest_sha256: Sha256
    rights_manifest_sha256: Sha256
    source_manifest_sha256: Sha256
    code_sha256: Sha256 | None = None
    config_sha256: Sha256 | None = None
    cohort: tuple[ProfileReleaseBuildCohortMemberRequest, ...]
    reconciliation_nonce: Sha256

    @model_validator(mode="after")
    def require_complete_unique_dev_cohort(self) -> ProfileReleaseBuildRequest:
        if len(self.cohort) != 24:
            raise ValueError("profile release requires exactly one complete DEV cohort of 24")
        if len({member.place_ref for member in self.cohort}) != 24:
            raise ValueError("profile release cohort members must be unique")
        if len({member.profile_sha256 for member in self.cohort}) != 24:
            raise ValueError("profile release cohort profiles must be unique")
        return self


class ProfileReleaseBuildDraftRequest(StrictContract):
    draft_ref: Annotated[
        str,
        Field(strict=True, pattern=r"^[A-Za-z0-9_-]{43}$"),
    ]
    nonce_sha256: Sha256


class ProfileReleaseBuildDraftCreateRequest(ProfileReleaseBuildRequest):
    draft_ref: Annotated[
        str,
        Field(strict=True, pattern=r"^[A-Za-z0-9_-]{43}$"),
    ]


class ProfileReleaseActivateRequest(StrictContract):
    expected_current_sha256: Sha256 | None = None
    nonce: Sha256


class ProfileReleaseRollbackRequest(StrictContract):
    expected_current_sha256: Sha256
    nonce: Sha256
    reason: Annotated[str, Field(strict=True, min_length=1, max_length=300)]


class ProfileReleaseMutationResponse(StrictContract):
    release_sha256: Sha256
    state: ProfileReleaseState
    receipt_sha256: Sha256 | None = None
    completion: str | None = None


class ProfileReleasePinResponse(StrictContract):
    release_sha256: Sha256
    pin_sha256: Sha256


class ProfileReleaseErrorResponse(StrictContract):
    detail: str


class ProfileReleaseUnknownOutcomeDetail(StrictContract):
    outcome: Literal["UNKNOWN"] = "UNKNOWN"
    action: Literal["BUILD", "APPROVE", "ACTIVATE", "ROLLBACK"]
    lookup_path: str


class ProfileReleaseUnknownOutcomeResponse(StrictContract):
    detail: ProfileReleaseUnknownOutcomeDetail


class ProfileReleaseRetryableAbortDetail(StrictContract):
    outcome: Literal["RETRYABLE_ABORT"] = "RETRYABLE_ABORT"
    action: Literal["BUILD", "APPROVE", "ACTIVATE", "ROLLBACK"]


class ProfileReleaseRetryableAbortResponse(StrictContract):
    detail: ProfileReleaseRetryableAbortDetail


class ProfileReleaseBuildUnavailableDetail(StrictContract):
    outcome: Literal["BUILD_UNAVAILABLE"] = "BUILD_UNAVAILABLE"
    action: Literal["BUILD"] = "BUILD"
    retry_path: Literal[
        "/internal/evaluation/profile-releases/build",
        "/internal/evaluation/profile-releases/build-drafts/build",
    ]


class ProfileReleaseBuildUnavailableResponse(StrictContract):
    detail: ProfileReleaseBuildUnavailableDetail


class ProfileReleaseDraftCleanupUnknownDetail(StrictContract):
    outcome: Literal["DRAFT_CLEANUP_UNKNOWN"] = "DRAFT_CLEANUP_UNKNOWN"
    action: Literal["BUILD"] = "BUILD"
    lookup_path: str
    retry_path: Literal["/internal/evaluation/profile-releases/build-drafts/build"]


class ProfileReleaseDraftCleanupUnknownResponse(StrictContract):
    detail: ProfileReleaseDraftCleanupUnknownDetail


_ResponseContracts = dict[int | str, dict[str, Any]]

_PROFILE_RELEASE_RESPONSES: _ResponseContracts = {
    status.HTTP_401_UNAUTHORIZED: {"model": ProfileReleaseErrorResponse},
    status.HTTP_403_FORBIDDEN: {"model": ProfileReleaseErrorResponse},
    status.HTTP_404_NOT_FOUND: {"model": ProfileReleaseErrorResponse},
    status.HTTP_409_CONFLICT: {"model": ProfileReleaseErrorResponse},
    status.HTTP_422_UNPROCESSABLE_CONTENT: {"model": ProfileReleaseErrorResponse},
    status.HTTP_503_SERVICE_UNAVAILABLE: {
        "model": ProfileReleaseUnknownOutcomeResponse | ProfileReleaseRetryableAbortResponse,
        "description": (
            "Mutation is either non-definitive and requires lookup reconciliation, "
            "or safely aborted after bounded serialization retries."
        ),
    },
}

_PROFILE_RELEASE_BUILD_RESPONSES: _ResponseContracts = {
    **_PROFILE_RELEASE_RESPONSES,
    status.HTTP_503_SERVICE_UNAVAILABLE: {
        "model": (
            ProfileReleaseUnknownOutcomeResponse
            | ProfileReleaseRetryableAbortResponse
            | ProfileReleaseBuildUnavailableResponse
        ),
        "description": ("BUILD is non-definitive, safely aborted, or unavailable before mutation."),
    },
}

_PROFILE_RELEASE_READ_RESPONSES: _ResponseContracts = {
    **_PROFILE_RELEASE_RESPONSES,
    status.HTTP_503_SERVICE_UNAVAILABLE: {
        "model": ProfileReleaseErrorResponse,
        "description": "Authoritative profile release state is temporarily unavailable.",
    },
}

_PROFILE_RELEASE_DRAFT_CREATE_RESPONSES: _ResponseContracts = {
    **_PROFILE_RELEASE_RESPONSES,
    status.HTTP_503_SERVICE_UNAVAILABLE: {
        "model": ProfileReleaseErrorResponse,
        "description": "Idempotent draft persistence is temporarily unavailable.",
    },
}

_PROFILE_RELEASE_DRAFT_BUILD_RESPONSES: _ResponseContracts = {
    **_PROFILE_RELEASE_RESPONSES,
    status.HTTP_503_SERVICE_UNAVAILABLE: {
        "model": (
            ProfileReleaseUnknownOutcomeResponse
            | ProfileReleaseRetryableAbortResponse
            | ProfileReleaseBuildUnavailableResponse
            | ProfileReleaseDraftCleanupUnknownResponse
        ),
        "description": (
            "BUILD is non-definitive, safely aborted, or committed while protected "
            "draft cleanup still requires an exact retry."
        ),
    },
}


def _require_evaluator(principal: Phase3Principal) -> None:
    if principal.role not in {"evaluator_a", "evaluator_b", "evaluator_c"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="phase 3 evaluator capability required",
        )


def _require_adjudicator(principal: Phase3Principal) -> None:
    if principal.role != "adjudicator":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="phase 3 adjudicator capability required",
        )


def _require_builder(principal: Phase3Principal) -> None:
    if principal.role != "builder":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="phase 3 builder capability required",
        )


def _require_approver(principal: Phase3Principal) -> None:
    if principal.role != "approver":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="phase 3 approver capability required",
        )


def _require_builder_or_approver(principal: Phase3Principal) -> None:
    if principal.role not in {"builder", "approver"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="phase 3 profile release read capability required",
        )


def _builder_principal(
    principal: Annotated[Phase3Principal, Depends(get_phase3_principal)],
) -> Phase3Principal:
    _require_builder(principal)
    return principal


def _approver_principal(
    principal: Annotated[Phase3Principal, Depends(get_phase3_principal)],
) -> Phase3Principal:
    _require_approver(principal)
    return principal


def _profile_release_reader_principal(
    principal: Annotated[Phase3Principal, Depends(get_phase3_principal)],
) -> Phase3Principal:
    _require_builder_or_approver(principal)
    return principal


def _builder_repository(
    principal: Annotated[Phase3Principal, Depends(_builder_principal)],
    repository: Annotated[EvaluationRepository, Depends(get_evaluation_repository)],
) -> EvaluationRepository:
    del principal
    return repository


def _approver_repository(
    principal: Annotated[Phase3Principal, Depends(_approver_principal)],
    repository: Annotated[EvaluationRepository, Depends(get_evaluation_repository)],
) -> EvaluationRepository:
    del principal
    return repository


def _profile_release_reader_repository(
    principal: Annotated[Phase3Principal, Depends(_profile_release_reader_principal)],
    repository: Annotated[EvaluationRepository, Depends(get_evaluation_repository)],
) -> EvaluationRepository:
    del principal
    return repository


def _require_evidence_reviewer(principal: Phase3Principal) -> None:
    # Phase 3 deliberately reuses the established builder capability for the
    # post-freeze review/build workflow. Evaluator, adjudicator, model-runner,
    # and approver credentials remain disjoint and receive no review rows.
    _require_builder(principal)


def _conflict(error: LabelExportBlocked) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="phase 3 label state is incomplete or stale",
    )


def _profile_release_conflict(error: Exception) -> HTTPException:
    del error
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="phase 3 profile release transition rejected",
    )


def _profile_release_unknown(error: ProfileReleaseUnknownOutcomeError) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={
            "outcome": "UNKNOWN",
            "action": error.action,
            "lookup_path": error.lookup_path,
        },
    )


def _profile_release_retryable_abort(
    error: ProfileReleaseRetryableAbortError,
) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={"outcome": "RETRYABLE_ABORT", "action": error.action},
    )


def _profile_release_build_unavailable(
    error: ProfileReleaseBuildUnavailableError,
) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={
            "outcome": "BUILD_UNAVAILABLE",
            "action": "BUILD",
            "retry_path": error.retry_path,
        },
    )


def _profile_release_read_unavailable(error: DBAPIError) -> HTTPException:
    del error
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="profile release state is temporarily unavailable",
    )


def _profile_release_draft_unavailable(error: DBAPIError) -> HTTPException:
    del error
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="profile release draft persistence is temporarily unavailable",
    )


def _profile_release_draft_cleanup_unknown(
    error: ProfileReleaseDraftCleanupUnknownError,
) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={
            "outcome": "DRAFT_CLEANUP_UNKNOWN",
            "action": "BUILD",
            "lookup_path": error.lookup_path,
            "retry_path": error.retry_path,
        },
    )


_PROFILE_RELEASE_AUTHORITY_ENVIRONMENTS = {
    "label_freeze": (
        "ITDA_PHASE3_PROFILE_RELEASE_LABEL_FREEZE_MANIFEST",
        "ITDA_PHASE3_PROFILE_RELEASE_LABEL_FREEZE_SHA256",
        "label_freeze_sha256",
    ),
    "candidate_manifest": (
        "ITDA_PHASE3_PROFILE_RELEASE_CANDIDATE_MANIFEST",
        "ITDA_PHASE3_PROFILE_RELEASE_CANDIDATE_SHA256",
        "candidate_manifest_sha256",
    ),
    "reviewed_manifest": (
        "ITDA_PHASE3_PROFILE_RELEASE_REVIEWED_MANIFEST",
        "ITDA_PHASE3_PROFILE_RELEASE_REVIEWED_SHA256",
        "reviewed_manifest_sha256",
    ),
    "rights_manifest": (
        "ITDA_PHASE3_PROFILE_RELEASE_RIGHTS_MANIFEST",
        "ITDA_PHASE3_PROFILE_RELEASE_RIGHTS_SHA256",
        "rights_manifest_sha256",
    ),
    "source_manifest": (
        "ITDA_PHASE3_PROFILE_RELEASE_SOURCE_MANIFEST",
        "ITDA_PHASE3_PROFILE_RELEASE_SOURCE_SHA256",
        "source_manifest_sha256",
    ),
}


class _ProfileReleaseAuthorityService:
    """Resolve release eligibility from server files and immutable review rows."""

    @staticmethod
    def _authority_request(
        candidate: ProfileReleaseBuildRequest | ProfileReleaseCandidate,
        *,
        principal: Phase3Principal,
    ) -> ProfileReleaseAuthorityRequest:
        candidate_manifest_sha256 = (
            candidate.candidate_run_sha256
            if isinstance(candidate, ProfileReleaseBuildRequest)
            else candidate.candidate_run_sha256
        )
        return ProfileReleaseAuthorityRequest(
            release_id=candidate.release_id,
            builder_principal=principal.actor_id,
            canonical_lineage_sha256=candidate.canonical_lineage_sha256,
            dev_lineage_sha256=candidate.dev_lineage_sha256,
            profile_schema_sha256=candidate.profile_schema_sha256,
            label_freeze_sha256=candidate.label_freeze_sha256,
            candidate_manifest_sha256=candidate_manifest_sha256,
            reviewed_manifest_sha256=candidate.reviewed_manifest_sha256,
            rights_manifest_sha256=candidate.rights_manifest_sha256,
            source_manifest_sha256=candidate.source_manifest_sha256,
        )

    @staticmethod
    def _configured_paths(
        request: ProfileReleaseAuthorityRequest,
    ) -> ProfileReleaseAuthorityPaths:
        configured_paths: dict[str, Path] = {}
        for name, (
            path_environment,
            digest_environment,
            request_field,
        ) in _PROFILE_RELEASE_AUTHORITY_ENVIRONMENTS.items():
            configured_path = os.environ.get(path_environment)
            configured_digest = os.environ.get(digest_environment)
            requested_digest = getattr(request, request_field)
            if (
                configured_path is None
                or configured_digest is None
                or len(configured_digest) != 64
                or any(character not in "0123456789abcdef" for character in configured_digest)
                or not hmac.compare_digest(configured_digest, requested_digest)
            ):
                raise ProfileReleaseAuthorityError("profile release authority bundle is invalid")
            configured_paths[name] = Path(configured_path)
        return ProfileReleaseAuthorityPaths(**configured_paths)

    @staticmethod
    def _verify_reviewed_records(
        candidate: ProfileReleaseCandidate,
        *,
        repository: EvaluationRepository,
    ) -> None:
        for member in candidate.cohort:
            reviewed = repository.get_reviewed_evidence_manifest(
                member.reviewed_evidence_manifest_sha256
            )
            if reviewed is None:
                raise ProfileReleaseAuthorityError("profile release authority bundle is invalid")
            if isinstance(reviewed, dict):
                manifest_sha256 = reviewed.get("manifest_sha256")
                candidate_manifest_sha256 = reviewed.get("candidate_manifest_sha256")
                accepted_review_set_sha256 = reviewed.get("accepted_review_set_sha256")
            else:
                manifest_sha256 = reviewed.manifest_sha256
                candidate_manifest_sha256 = reviewed.candidate_manifest_sha256
                accepted_review_set_sha256 = reviewed.accepted_review_set_sha256
            if not (
                isinstance(manifest_sha256, str)
                and hmac.compare_digest(
                    manifest_sha256,
                    member.reviewed_evidence_manifest_sha256,
                )
                and isinstance(candidate_manifest_sha256, str)
                and hmac.compare_digest(
                    candidate_manifest_sha256,
                    member.candidate_manifest_sha256,
                )
                and isinstance(accepted_review_set_sha256, str)
                and hmac.compare_digest(
                    accepted_review_set_sha256,
                    member.accepted_review_set_sha256,
                )
            ):
                raise ProfileReleaseAuthorityError("profile release authority bundle is invalid")

    def resolve_request(
        self,
        request: ProfileReleaseBuildRequest,
        *,
        principal: Phase3Principal,
        repository: EvaluationRepository,
    ) -> ProfileReleaseBuildAuthorityResolution:
        return self._resolve(
            self._authority_request(request, principal=principal),
            repository=repository,
        )

    def resolve_candidate(
        self,
        candidate: ProfileReleaseCandidate,
        *,
        principal: Phase3Principal,
        repository: EvaluationRepository,
    ) -> ProfileReleaseBuildAuthorityResolution:
        resolved = self._resolve(
            self._authority_request(candidate, principal=principal),
            repository=repository,
        )
        if resolved.candidate != candidate:
            raise ProfileReleaseAuthorityError("profile release authority bundle is invalid")
        return resolved

    def _resolve(
        self,
        request: ProfileReleaseAuthorityRequest,
        *,
        repository: EvaluationRepository,
    ) -> ProfileReleaseBuildAuthorityResolution:
        try:
            authority_registry_id = parse_profile_release_authority_registry_id(
                os.environ.get("ITDA_PROFILE_RELEASE_AUTHORITY_REGISTRY_ID")
            )
            builder_database_principal = repository.profile_release_builder_database_principal()
        except (DBAPIError, RuntimeError):
            raise ProfileReleaseAuthorityError(
                "profile release authority bundle is invalid"
            ) from None
        resolution = resolve_authoritative_profile_release_build_authority(
            request=request,
            paths=self._configured_paths(request),
            authority_registry_id=authority_registry_id,
            builder_database_principal=builder_database_principal,
        )
        candidate = resolution.candidate
        if not isinstance(candidate, ProfileReleaseCandidate):
            raise ProfileReleaseAuthorityError("profile release authority bundle is invalid")
        try:
            self._verify_reviewed_records(candidate, repository=repository)
        except DBAPIError:
            raise ProfileReleaseAuthorityError(
                "profile release authority bundle is invalid"
            ) from None
        return resolution


_PROFILE_RELEASE_AUTHORITY_SERVICE = _ProfileReleaseAuthorityService()


def _profile_release_authority_service() -> _ProfileReleaseAuthorityService:
    return _PROFILE_RELEASE_AUTHORITY_SERVICE


_OFFICIAL_SOURCE_MAX_BYTES = 128 * 1024
_OFFICIAL_SOURCE_ENVIRONMENT = "ITDA_PHASE3_OFFICIAL_SOURCE_MANIFEST"
_OFFICIAL_SOURCE_SHA256_ENVIRONMENT = "ITDA_PHASE3_OFFICIAL_SOURCE_SHA256"
_E2E_SOURCE_FIXTURE_SHA256 = "e14e074facdbe84c4d61ded5eb9b9f402320b1d1799cc466f58fcca2e4a68f28"
_E2E_SOURCE_ASSIGNMENT_ID = "synthetic-runtime-assignment-alpha"
_E2E_ATTEMPT_ASSIGNMENT_PATTERN = re.compile(
    rf"{re.escape(_E2E_SOURCE_ASSIGNMENT_ID)}-r[0-9]+-e[0-9]+-w[0-9]+"
)
_E2E_SOURCE_FIXTURE = (
    Path(__file__).resolve().parents[5] / "fixtures" / "synthetic" / "phase3" / "e2e-runtime.json"
)
_SOURCE_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "synthetic_only",
        "assignment",
        "rubric_reference",
        "sources",
        "evidence_items",
        "release",
    }
)
_ASSIGNMENT_FIELDS = frozenset({"assignment_id", "rubric_version", "source_snapshot_version"})
_SOURCE_FIELDS = frozenset({"source_id", "lane", "text_ko"})
_EVIDENCE_FIELDS = frozenset({"evidence_id", "source_id", "lane", "dedup_cluster_id"})


def _closed_object(value: object, *, fields: frozenset[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise LabelExportBlocked("phase 3 label state is incomplete or stale")
    return cast(dict[str, object], value)


def _read_bounded_regular_file(path: Path, *, max_bytes: int = _OFFICIAL_SOURCE_MAX_BYTES) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise LabelExportBlocked("phase 3 label state is incomplete or stale") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > max_bytes:
            raise LabelExportBlocked("phase 3 label state is incomplete or stale")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if len(raw) != before.st_size or len(raw) > max_bytes or identity_before != identity_after:
            raise LabelExportBlocked("phase 3 label state is incomplete or stale")
        return raw
    except OSError as error:
        raise LabelExportBlocked("phase 3 label state is incomplete or stale") from error
    finally:
        os.close(descriptor)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise LabelExportBlocked("phase 3 label state is incomplete or stale")
        result[key] = value
    return result


def _load_official_source_manifest(assignment_id: str) -> AdjudicationSourceManifest:
    e2e_mode = os.environ.get("ITDA_E2E_PHASE3_TEST_SUPPORT") == "1"
    if e2e_mode:
        path = _E2E_SOURCE_FIXTURE
    else:
        configured = os.environ.get(_OFFICIAL_SOURCE_ENVIRONMENT)
        if not configured:
            raise LabelExportBlocked("phase 3 label state is incomplete or stale")
        path = Path(configured)
    raw = _read_bounded_regular_file(path)
    expected_raw_sha256 = (
        _E2E_SOURCE_FIXTURE_SHA256
        if e2e_mode
        else os.environ.get(_OFFICIAL_SOURCE_SHA256_ENVIRONMENT)
    )
    if (
        expected_raw_sha256 is None
        or len(expected_raw_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_raw_sha256)
        or hashlib.sha256(raw).hexdigest() != expected_raw_sha256
    ):
        raise LabelExportBlocked("phase 3 label state is incomplete or stale")
    try:
        decoded = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LabelExportBlocked("phase 3 label state is incomplete or stale") from error
    payload = _closed_object(decoded, fields=_SOURCE_MANIFEST_FIELDS)
    if e2e_mode and payload["synthetic_only"] is not True:
        raise LabelExportBlocked("phase 3 label state is incomplete or stale")
    assignment = _closed_object(payload["assignment"], fields=_ASSIGNMENT_FIELDS)
    if assignment["assignment_id"] != assignment_id:
        namespaced_e2e_assignment = (
            e2e_mode
            and assignment["assignment_id"] == _E2E_SOURCE_ASSIGNMENT_ID
            and _E2E_ATTEMPT_ASSIGNMENT_PATTERN.fullmatch(assignment_id) is not None
        )
        if not namespaced_e2e_assignment:
            raise LabelExportBlocked("phase 3 label state is incomplete or stale")
    sources_value = payload["sources"]
    evidence_value = payload["evidence_items"]
    if not isinstance(sources_value, list) or not isinstance(evidence_value, list):
        raise LabelExportBlocked("phase 3 label state is incomplete or stale")
    sources = tuple(_closed_object(source, fields=_SOURCE_FIELDS) for source in sources_value)
    evidence_items = tuple(
        _closed_object(evidence, fields=_EVIDENCE_FIELDS) for evidence in evidence_value
    )
    evidence_by_source: dict[str, list[str]] = {}
    source_lanes = {str(source["source_id"]): source["lane"] for source in sources}
    for evidence in evidence_items:
        source_id = str(evidence["source_id"])
        if source_lanes.get(source_id) != evidence["lane"]:
            raise LabelExportBlocked("phase 3 label state is incomplete or stale")
        evidence_by_source.setdefault(source_id, []).append(str(evidence["evidence_id"]))
    try:
        official_sources = tuple(
            sorted(
                (
                    AdjudicationOfficialSource(
                        source_id=str(source["source_id"]),
                        lane=EvidenceLane(str(source["lane"])),
                        original_text=str(source["text_ko"]),
                        source_text_sha256=hashlib.sha256(
                            str(source["text_ko"]).encode("utf-8")
                        ).hexdigest(),
                        evidence_ids=tuple(
                            sorted(evidence_by_source.get(str(source["source_id"]), ()))
                        ),
                    )
                    for source in sources
                ),
                key=lambda item: item.source_id,
            )
        )
        return AdjudicationSourceManifest(
            assignment_id=assignment_id,
            source_snapshot_version=str(assignment["source_snapshot_version"]),
            sources=official_sources,
        )
    except ValidationError as error:
        raise LabelExportBlocked("phase 3 label state is incomplete or stale") from error


_CANDIDATE_MANIFEST_ENVIRONMENT = "ITDA_PHASE3_CANDIDATE_MANIFEST"
_CANDIDATE_MANIFEST_SHA256_ENVIRONMENT = "ITDA_PHASE3_CANDIDATE_MANIFEST_SHA256"
_CANDIDATE_MANIFEST_MAX_BYTES = 8 * 1024 * 1024


def _load_candidate_manifest() -> dict[str, Any]:
    configured = os.environ.get(_CANDIDATE_MANIFEST_ENVIRONMENT)
    expected = os.environ.get(_CANDIDATE_MANIFEST_SHA256_ENVIRONMENT)
    if not configured or expected is None:
        raise LabelExportBlocked("phase 3 evidence candidate state is incomplete or stale")
    raw = _read_bounded_regular_file(Path(configured), max_bytes=_CANDIDATE_MANIFEST_MAX_BYTES)
    if (
        len(expected) != 64
        or any(character not in "0123456789abcdef" for character in expected)
        or hashlib.sha256(raw).hexdigest() != expected
    ):
        raise LabelExportBlocked("phase 3 evidence candidate state is incomplete or stale")
    try:
        decoded = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LabelExportBlocked(
            "phase 3 evidence candidate state is incomplete or stale"
        ) from error
    if not isinstance(decoded, dict):
        raise LabelExportBlocked("phase 3 evidence candidate state is incomplete or stale")
    return cast(dict[str, Any], decoded)


def _bind_evidence_review(
    request: EvidenceReviewRequest,
    *,
    candidate_id: str,
    principal: Phase3Principal,
    queue: EvidenceReviewQueue,
    parent_review_sha256: str | None = None,
    correction_reason: str | None = None,
) -> EvidenceReviewRevision:
    if request.candidate_manifest_sha256 != queue.candidate_manifest_sha256:
        raise LabelExportBlocked("phase 3 evidence candidate state is incomplete or stale")
    candidate = next(
        (
            candidate
            for lane in queue.lanes
            for candidate in lane.candidates
            if candidate.candidate_id == candidate_id
        ),
        None,
    )
    if (
        candidate is None
        or candidate.candidate_sha256 != request.candidate_sha256
        or candidate.lane is not request.lane
    ):
        raise LabelExportBlocked("phase 3 evidence candidate state is incomplete or stale")
    return EvidenceReviewRevision(
        candidate_manifest_sha256=queue.candidate_manifest_sha256,
        candidate_id=candidate.candidate_id,
        candidate_sha256=candidate.candidate_sha256,
        lane=candidate.lane,
        decision=request.decision,
        reason=request.reason,
        reviewer_pseudonym=principal.actor_id,
        reviewed_at=request.reviewed_at or datetime.now(UTC),
        provenance=queue.provenance,
        parent_review_sha256=parent_review_sha256,
        correction_reason=correction_reason,
    )


def _server_bound_revision(
    payload: dict[str, object],
    *,
    principal: Phase3Principal,
    parent_revision_sha256: str | None = None,
) -> RawLabelRevision:
    if _CLIENT_IDENTITY_FIELDS & payload.keys():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="client identity fields are forbidden",
        )
    try:
        bound = dict(payload)
        if parent_revision_sha256 is not None:
            if "parent_revision_sha256" in bound:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="correction parent is path-bound",
                )
            bound["parent_revision_sha256"] = parent_revision_sha256
        judgments = bound.get("judgments")
        if not isinstance(judgments, list):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="judgments must be an ordered array",
            )
        bound["judgments"] = [
            AttributeJudgment.model_validate(item).model_dump(mode="json") for item in judgments
        ]
        bound["evaluator_pseudonym"] = principal.actor_id
        return RawLabelRevision.model_validate(bound)
    except ValidationError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="label revision contract rejected",
        ) from error


@router.post(
    "/revisions",
    response_model=StoredLabelRevision,
    status_code=status.HTTP_201_CREATED,
)
def append_revision(
    payload: Annotated[dict[str, object], Body()],
    principal: Annotated[Phase3Principal, Depends(get_phase3_principal)],
    repository: Annotated[EvaluationRepository, Depends(get_evaluation_repository)],
) -> StoredLabelRevision:
    _require_evaluator(principal)
    revision = _server_bound_revision(payload, principal=principal)
    return repository.append_revision(revision)


@router.post(
    "/revisions/{parent_revision_sha256}/corrections",
    response_model=StoredLabelRevision,
    status_code=status.HTTP_201_CREATED,
)
def append_correction(
    parent_revision_sha256: str,
    payload: Annotated[dict[str, object], Body()],
    principal: Annotated[Phase3Principal, Depends(get_phase3_principal)],
    repository: Annotated[EvaluationRepository, Depends(get_evaluation_repository)],
) -> StoredLabelRevision:
    _require_evaluator(principal)
    revision = _server_bound_revision(
        payload,
        principal=principal,
        parent_revision_sha256=parent_revision_sha256,
    )
    return repository.append_correction(revision)


@router.post(
    "/revisions/{revision_sha256}/accepted-head",
    response_model=AcceptedHeadReceipt,
)
def select_accepted_head(
    revision_sha256: str,
    request: AcceptedHeadRequest,
    principal: Annotated[Phase3Principal, Depends(get_phase3_principal)],
    repository: Annotated[EvaluationRepository, Depends(get_evaluation_repository)],
) -> AcceptedHeadReceipt:
    _require_adjudicator(principal)
    try:
        return repository.select_accepted_head(
            revision_sha256,
            reason=request.reason,
            selected_at=request.selected_at,
            expected_chain_sha256=request.expected_chain_sha256,
        )
    except LabelExportBlocked as error:
        raise _conflict(error) from error


@router.get(
    "/revisions/{revision_sha256}/receipt",
    response_model=StoredLabelRevision,
)
def get_own_revision_receipt(
    revision_sha256: Sha256,
    principal: Annotated[Phase3Principal, Depends(get_phase3_principal)],
    repository: Annotated[EvaluationRepository, Depends(get_evaluation_repository)],
) -> StoredLabelRevision:
    _require_evaluator(principal)
    stored = repository.get_own_revision(
        revision_sha256,
        evaluator_pseudonym=principal.actor_id,
    )
    if stored is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="revision receipt not found",
        )
    return stored


@router.get("/revisions/own-chain", response_model=tuple[StoredLabelRevision, ...])
def get_own_chain(
    principal: Annotated[Phase3Principal, Depends(get_phase3_principal)],
    repository: Annotated[EvaluationRepository, Depends(get_evaluation_repository)],
) -> tuple[StoredLabelRevision, ...]:
    _require_evaluator(principal)
    return repository.get_own_chain(evaluator_pseudonym=principal.actor_id)


@router.get("/status", response_model=tuple[LabelSubmissionStatus, ...])
def get_submission_status(
    principal: Annotated[Phase3Principal, Depends(get_phase3_principal)],
    repository: Annotated[EvaluationRepository, Depends(get_evaluation_repository)],
) -> tuple[LabelSubmissionStatus, ...]:
    _require_builder(principal)
    return repository.get_submission_status()


@router.get(
    "/assignments/{assignment_id}/accepted-heads",
    response_model=tuple[AcceptedRevisionSelection, ...],
)
def get_accepted_heads(
    assignment_id: str,
    principal: Annotated[Phase3Principal, Depends(get_phase3_principal)],
    repository: Annotated[EvaluationRepository, Depends(get_evaluation_repository)],
) -> tuple[AcceptedRevisionSelection, ...]:
    _require_adjudicator(principal)
    try:
        return tuple(head.selection for head in repository.get_accepted_heads(assignment_id))
    except LabelExportBlocked as error:
        raise _conflict(error) from error


@router.get(
    "/assignments/{assignment_id}/adjudication-projection",
    response_model=AdjudicationProjection,
)
def get_adjudication_projection(
    assignment_id: str,
    principal: Annotated[Phase3Principal, Depends(get_phase3_principal)],
) -> AdjudicationProjection:
    _require_adjudicator(principal)
    try:
        official_source = _load_official_source_manifest(assignment_id)
        repository = get_evaluation_repository(principal)
        return repository.get_adjudicator_projection(assignment_id, official_source)
    except LabelExportBlocked as error:
        raise _conflict(error) from error


@router.post(
    "/assignments/{assignment_id}/review-triggers",
    response_model=tuple[ReviewTrigger, ...],
)
def derive_review_triggers(
    assignment_id: str,
    principal: Annotated[Phase3Principal, Depends(get_phase3_principal)],
    repository: Annotated[EvaluationRepository, Depends(get_evaluation_repository)],
) -> tuple[ReviewTrigger, ...]:
    _require_adjudicator(principal)
    try:
        return repository.derive_and_store_review_triggers(assignment_id)
    except LabelExportBlocked as error:
        raise _conflict(error) from error


@router.post(
    "/assignments/{assignment_id}/review-trigger-resolution",
    response_model=ReviewTriggerResolution,
)
def resolve_review_trigger(
    assignment_id: str,
    request: ReviewResolutionRequest,
    principal: Annotated[Phase3Principal, Depends(get_phase3_principal)],
    repository: Annotated[EvaluationRepository, Depends(get_evaluation_repository)],
) -> ReviewTriggerResolution:
    _require_adjudicator(principal)
    resolution = ReviewTriggerResolution(
        review_trigger_sha256=request.review_trigger_sha256,
        reason=request.reason,
        adjudicator_pseudonym=principal.actor_id,
        resolved_at=request.resolved_at or datetime.now(UTC),
    )
    try:
        return repository.resolve_review_trigger(assignment_id, resolution)
    except LabelExportBlocked as error:
        raise _conflict(error) from error


@router.post(
    "/assignments/{assignment_id}/aggregate",
    response_model=AdjudicatedLabelExport,
)
def aggregate_labels(
    assignment_id: str,
    request: AggregateRequest,
    principal: Annotated[Phase3Principal, Depends(get_phase3_principal)],
    repository: Annotated[EvaluationRepository, Depends(get_evaluation_repository)],
) -> AdjudicatedLabelExport:
    _require_adjudicator(principal)
    adjudications = tuple(
        AdjudicatedAttributeValue(
            attribute_id=item.attribute_id,
            exact_median=item.exact_median,
            adjudicated_value=item.adjudicated_value,
            reason=item.reason,
            adjudicator_pseudonym=principal.actor_id,
            adjudicated_at=item.adjudicated_at or datetime.now(UTC),
        )
        for item in request.adjudications
    )
    try:
        return repository.aggregate_and_store(
            assignment_id,
            adjudications=adjudications,
        )
    except LabelExportBlocked as error:
        raise _conflict(error) from error


@router.get("/evidence-review/candidates", response_model=EvidenceReviewQueue)
def get_evidence_review_candidates(
    principal: Annotated[Phase3Principal, Depends(get_phase3_principal)],
    repository: Annotated[EvaluationRepository, Depends(get_evaluation_repository)],
) -> EvidenceReviewQueue:
    _require_evidence_reviewer(principal)
    try:
        return repository.register_candidate_manifest(_load_candidate_manifest())
    except LabelExportBlocked as error:
        raise _conflict(error) from error


@router.post(
    "/evidence-review/candidates/{candidate_id}/reviews",
    response_model=EvidenceReviewReceipt,
    status_code=status.HTTP_201_CREATED,
)
def append_evidence_review(
    candidate_id: Sha256,
    request: EvidenceReviewRequest,
    principal: Annotated[Phase3Principal, Depends(get_phase3_principal)],
    repository: Annotated[EvaluationRepository, Depends(get_evaluation_repository)],
) -> EvidenceReviewReceipt:
    _require_evidence_reviewer(principal)
    try:
        queue = repository.register_candidate_manifest(_load_candidate_manifest())
        revision = _bind_evidence_review(
            request, candidate_id=candidate_id, principal=principal, queue=queue
        )
        return repository.append_evidence_review(revision)
    except LabelExportBlocked as error:
        raise _conflict(error) from error


@router.post(
    "/evidence-review/candidates/{candidate_id}/reviews/{parent_review_sha256}/corrections",
    response_model=EvidenceReviewReceipt,
    status_code=status.HTTP_201_CREATED,
)
def append_evidence_review_correction(
    candidate_id: Sha256,
    parent_review_sha256: Sha256,
    request: EvidenceReviewCorrectionRequest,
    principal: Annotated[Phase3Principal, Depends(get_phase3_principal)],
    repository: Annotated[EvaluationRepository, Depends(get_evaluation_repository)],
) -> EvidenceReviewReceipt:
    _require_evidence_reviewer(principal)
    try:
        queue = repository.register_candidate_manifest(_load_candidate_manifest())
        revision = _bind_evidence_review(
            request,
            candidate_id=candidate_id,
            principal=principal,
            queue=queue,
            parent_review_sha256=parent_review_sha256,
            correction_reason=request.correction_reason,
        )
        return repository.append_evidence_review_correction(revision)
    except LabelExportBlocked as error:
        raise _conflict(error) from error


@router.get(
    "/evidence-review/manifests/{candidate_manifest_sha256}/candidates/{candidate_id}/chain",
    response_model=EvidenceReviewChain,
)
def get_evidence_review_chain(
    candidate_manifest_sha256: Sha256,
    candidate_id: Sha256,
    principal: Annotated[Phase3Principal, Depends(get_phase3_principal)],
    repository: Annotated[EvaluationRepository, Depends(get_evaluation_repository)],
) -> EvidenceReviewChain:
    _require_evidence_reviewer(principal)
    try:
        queue = repository.register_candidate_manifest(_load_candidate_manifest())
        if queue.candidate_manifest_sha256 != candidate_manifest_sha256:
            raise LabelExportBlocked("phase 3 evidence candidate state is incomplete or stale")
        return repository.get_evidence_review_chain(
            candidate_manifest_sha256=candidate_manifest_sha256,
            candidate_id=candidate_id,
        )
    except LabelExportBlocked as error:
        if str(error) == "evidence review chain is incomplete or stale":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="evidence review chain not found",
            ) from error
        raise _conflict(error) from error


@router.post(
    "/evidence-review/reviews/{review_sha256}/accepted-head",
    response_model=AcceptedEvidenceReviewHead,
)
def select_evidence_review_head(
    review_sha256: Sha256,
    request: EvidenceReviewHeadRequest,
    principal: Annotated[Phase3Principal, Depends(get_phase3_principal)],
    repository: Annotated[EvaluationRepository, Depends(get_evaluation_repository)],
) -> AcceptedEvidenceReviewHead:
    _require_evidence_reviewer(principal)
    try:
        queue = repository.register_candidate_manifest(_load_candidate_manifest())
        if queue.candidate_manifest_sha256 != request.candidate_manifest_sha256:
            raise LabelExportBlocked("phase 3 evidence candidate state is incomplete or stale")
        candidate = next(
            (
                candidate
                for lane in queue.lanes
                for candidate in lane.candidates
                if candidate.candidate_id == request.candidate_id
            ),
            None,
        )
        if (
            candidate is None
            or candidate.candidate_sha256 != request.candidate_sha256
            or candidate.lane is not request.lane
        ):
            raise LabelExportBlocked("phase 3 evidence candidate state is incomplete or stale")
        chain = repository.get_evidence_review_chain(
            candidate_manifest_sha256=request.candidate_manifest_sha256,
            candidate_id=request.candidate_id,
        )
        if chain.tip_review_sha256 != review_sha256:
            raise LabelExportBlocked("phase 3 evidence review state is incomplete or stale")
        return repository.select_evidence_review_head(
            review_sha256,
            expected_chain_sha256=request.expected_chain_sha256,
            selected_by=principal.actor_id,
            selection_reason=request.selection_reason,
            selected_at=request.selected_at or datetime.now(UTC),
        )
    except LabelExportBlocked as error:
        raise _conflict(error) from error


@router.post(
    "/evidence-review/finalize",
    response_model=ReviewedEvidenceManifest,
    status_code=status.HTTP_201_CREATED,
)
def finalize_reviewed_evidence_manifest(
    request: ReviewedEvidenceFinalizeRequest,
    principal: Annotated[Phase3Principal, Depends(get_phase3_principal)],
    repository: Annotated[EvaluationRepository, Depends(get_evaluation_repository)],
) -> ReviewedEvidenceManifest:
    _require_evidence_reviewer(principal)
    try:
        queue = repository.register_candidate_manifest(_load_candidate_manifest())
        if queue.candidate_manifest_sha256 != request.candidate_manifest_sha256:
            raise LabelExportBlocked("phase 3 evidence candidate state is incomplete or stale")
        return repository.finalize_reviewed_evidence_manifest(
            request.candidate_manifest_sha256,
            finalized_by=principal.actor_id,
            finalized_at=request.finalized_at or datetime.now(UTC),
        )
    except LabelExportBlocked as error:
        raise _conflict(error) from error


@router.get(
    "/evidence-review/reviewed-manifests/{manifest_sha256}",
    response_model=ReviewedEvidenceManifest,
)
def get_reviewed_evidence_manifest(
    manifest_sha256: Sha256,
    principal: Annotated[Phase3Principal, Depends(get_phase3_principal)],
    repository: Annotated[EvaluationRepository, Depends(get_evaluation_repository)],
) -> ReviewedEvidenceManifest:
    _require_evidence_reviewer(principal)
    manifest = repository.get_reviewed_evidence_manifest(manifest_sha256)
    if manifest is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="reviewed evidence manifest not found",
        )
    return manifest


@router.post(
    "/profile-releases/build",
    response_model=ProfileReleaseBuildOutcome,
    status_code=status.HTTP_201_CREATED,
    responses=_PROFILE_RELEASE_BUILD_RESPONSES,
)
def build_profile_release(
    request: ProfileReleaseBuildRequest,
    principal: Annotated[Phase3Principal, Depends(_builder_principal)],
    repository: Annotated[EvaluationRepository, Depends(_builder_repository)],
    authority: Annotated[
        _ProfileReleaseAuthorityService,
        Depends(_profile_release_authority_service),
    ],
) -> ProfileReleaseBuildOutcome:
    try:
        authority_resolution = authority.resolve_request(
            request,
            principal=principal,
            repository=repository,
        )
        return repository.build_profile_release(
            authority_resolution,
            authenticated_principal=principal.actor_id,
            reconciliation_nonce=request.reconciliation_nonce,
        )
    except ProfileReleaseUnknownOutcomeError as error:
        raise _profile_release_unknown(error) from error
    except ProfileReleaseRetryableAbortError as error:
        raise _profile_release_retryable_abort(error) from error
    except ProfileReleaseBuildUnavailableError as error:
        raise _profile_release_build_unavailable(error) from error
    except ProfileReleaseAuthorityError as error:
        raise _profile_release_build_unavailable(
            ProfileReleaseBuildUnavailableError(
                retry_path="/internal/evaluation/profile-releases/build"
            )
        ) from error
    except DBAPIError as error:
        if isinstance(error, IntegrityError):
            raise _profile_release_conflict(error) from error
        nonce_sha256 = hashlib.sha256(request.reconciliation_nonce.encode("ascii")).hexdigest()
        unknown = ProfileReleaseUnknownOutcomeError(
            action="BUILD",
            lookup_path=(
                f"/internal/evaluation/profile-releases/build-receipts/by-nonce/{nonce_sha256}"
            ),
        )
        raise _profile_release_unknown(unknown) from error
    except ValidationError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="profile release build request is structurally invalid",
        ) from error
    except (ValueError, ProfileReleaseReplayError) as error:
        raise _profile_release_conflict(error) from error


@router.post(
    "/profile-releases/build-drafts",
    response_model=ProfileReleaseBuildDraftReference,
    status_code=status.HTTP_201_CREATED,
    responses=_PROFILE_RELEASE_DRAFT_CREATE_RESPONSES,
)
def create_profile_release_build_draft(
    request: ProfileReleaseBuildDraftCreateRequest,
    principal: Annotated[Phase3Principal, Depends(_builder_principal)],
    repository: Annotated[EvaluationRepository, Depends(_builder_repository)],
    authority: Annotated[
        _ProfileReleaseAuthorityService,
        Depends(_profile_release_authority_service),
    ],
) -> ProfileReleaseBuildDraftReference:
    try:
        authority_resolution = authority.resolve_request(
            request,
            principal=principal,
            repository=repository,
        )
        candidate = authority_resolution.candidate
        if not isinstance(candidate, ProfileReleaseCandidate):
            raise ProfileReleaseAuthorityError("profile release authority bundle is invalid")
        return repository.create_profile_release_build_draft(
            candidate,
            authenticated_principal=principal.actor_id,
            reconciliation_nonce=request.reconciliation_nonce,
            draft_ref=request.draft_ref,
        )
    except DBAPIError as error:
        if isinstance(error, IntegrityError):
            raise _profile_release_conflict(error) from error
        raise _profile_release_draft_unavailable(error) from error
    except ProfileReleaseAuthorityError as error:
        del error
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="profile release draft persistence is temporarily unavailable",
        ) from None
    except ValidationError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="profile release build request is structurally invalid",
        ) from error
    except (ValueError, ProfileReleaseReplayError) as error:
        raise _profile_release_conflict(error) from error


@router.post(
    "/profile-releases/build-drafts/build",
    response_model=ProfileReleaseBuildOutcome,
    status_code=status.HTTP_201_CREATED,
    responses=_PROFILE_RELEASE_DRAFT_BUILD_RESPONSES,
)
def build_profile_release_from_draft(
    request: ProfileReleaseBuildDraftRequest,
    principal: Annotated[Phase3Principal, Depends(_builder_principal)],
    repository: Annotated[EvaluationRepository, Depends(_builder_repository)],
    authority: Annotated[
        _ProfileReleaseAuthorityService,
        Depends(_profile_release_authority_service),
    ],
) -> ProfileReleaseBuildOutcome:
    try:
        stored_candidate = repository.get_profile_release_build_draft_candidate(
            request.draft_ref,
            authenticated_principal=principal.actor_id,
            nonce_sha256=request.nonce_sha256,
        )
        if stored_candidate is None:
            return repository.build_profile_release_from_draft(
                request.draft_ref,
                authenticated_principal=principal.actor_id,
                nonce_sha256=request.nonce_sha256,
                reconciliation_only=True,
            )
        authority_resolution = authority.resolve_candidate(
            stored_candidate,
            principal=principal,
            repository=repository,
        )
        return repository.build_profile_release_from_draft(
            request.draft_ref,
            authenticated_principal=principal.actor_id,
            nonce_sha256=request.nonce_sha256,
            authority_resolution=authority_resolution,
        )
    except ProfileReleaseDraftCleanupUnknownError as error:
        raise _profile_release_draft_cleanup_unknown(error) from error
    except ProfileReleaseUnknownOutcomeError as error:
        raise _profile_release_unknown(error) from error
    except ProfileReleaseRetryableAbortError as error:
        raise _profile_release_retryable_abort(error) from error
    except ProfileReleaseBuildUnavailableError as error:
        raise _profile_release_build_unavailable(error) from error
    except ProfileReleaseAuthorityError as error:
        raise _profile_release_build_unavailable(
            ProfileReleaseBuildUnavailableError(
                retry_path="/internal/evaluation/profile-releases/build-drafts/build"
            )
        ) from error
    except DBAPIError as error:
        if isinstance(error, IntegrityError):
            raise _profile_release_conflict(error) from error
        raise _profile_release_unknown(
            ProfileReleaseUnknownOutcomeError(
                action="BUILD",
                lookup_path=(
                    "/internal/evaluation/profile-releases/build-receipts/by-nonce/"
                    f"{request.nonce_sha256}"
                ),
            )
        ) from error
    except (ValueError, ProfileReleaseReplayError) as error:
        raise _profile_release_conflict(error) from error


def _unknown_profile_release_outcome() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="profile release outcome UNKNOWN",
    )


@router.get(
    "/profile-releases/build-receipts/by-nonce/{nonce_sha256}",
    response_model=ProfileReleaseBuildOutcome,
    responses=_PROFILE_RELEASE_READ_RESPONSES,
)
def get_profile_release_build_outcome(
    nonce_sha256: Sha256,
    principal: Annotated[Phase3Principal, Depends(_builder_principal)],
    repository: Annotated[EvaluationRepository, Depends(_builder_repository)],
) -> ProfileReleaseBuildOutcome:
    try:
        outcome = repository.get_profile_release_build_outcome_by_nonce(
            nonce_sha256,
            principal.actor_id,
        )
    except DBAPIError as error:
        raise _profile_release_read_unavailable(error) from error
    except (ValueError, ProfileReleaseReplayError) as error:
        raise _profile_release_conflict(error) from error
    if outcome is None:
        raise _unknown_profile_release_outcome()
    return outcome


@router.get(
    "/profile-releases/active-pointer",
    response_model=ProfileReleaseActivePointerProjection,
    responses=_PROFILE_RELEASE_READ_RESPONSES,
)
def get_profile_release_active_pointer(
    principal: Annotated[Phase3Principal, Depends(_profile_release_reader_principal)],
    repository: Annotated[EvaluationRepository, Depends(_profile_release_reader_repository)],
) -> ProfileReleaseActivePointerProjection:
    del principal
    try:
        return repository.get_profile_release_active_pointer()
    except DBAPIError as error:
        raise _profile_release_read_unavailable(error) from error
    except (ValueError, ProfileReleaseReplayError) as error:
        raise _profile_release_conflict(error) from error


@router.get(
    "/profile-releases/transition-receipts/by-nonce/{nonce_sha256}",
    response_model=ProfileReleaseTransitionOutcome,
    responses=_PROFILE_RELEASE_READ_RESPONSES,
)
def get_profile_release_transition_outcome(
    nonce_sha256: Sha256,
    principal: Annotated[Phase3Principal, Depends(_approver_principal)],
    repository: Annotated[EvaluationRepository, Depends(_approver_repository)],
) -> ProfileReleaseTransitionOutcome:
    try:
        outcome = repository.get_profile_release_transition_outcome_by_nonce(
            nonce_sha256,
            principal.actor_id,
        )
    except DBAPIError as error:
        raise _profile_release_read_unavailable(error) from error
    except (ValueError, ProfileReleaseReplayError) as error:
        raise _profile_release_conflict(error) from error
    if outcome is None:
        raise _unknown_profile_release_outcome()
    return outcome


@router.get(
    "/profile-releases/{release_sha256}/state",
    response_model=ProfileReleaseStateProjection,
    responses=_PROFILE_RELEASE_READ_RESPONSES,
)
def get_profile_release_state(
    release_sha256: Sha256,
    principal: Annotated[Phase3Principal, Depends(_profile_release_reader_principal)],
    repository: Annotated[EvaluationRepository, Depends(_profile_release_reader_repository)],
) -> ProfileReleaseStateProjection:
    del principal
    try:
        projection = repository.get_profile_release_state(release_sha256)
    except DBAPIError as error:
        raise _profile_release_read_unavailable(error) from error
    except (ValueError, ProfileReleaseReplayError) as error:
        raise _profile_release_conflict(error) from error
    if projection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="profile release not found",
        )
    return projection


@router.post(
    "/profile-releases/{release_sha256}/approve",
    response_model=ProfileReleaseMutationResponse,
    responses=_PROFILE_RELEASE_RESPONSES,
)
def approve_profile_release(
    release_sha256: Sha256,
    principal: Annotated[Phase3Principal, Depends(_approver_principal)],
    repository: Annotated[EvaluationRepository, Depends(_approver_repository)],
) -> ProfileReleaseMutationResponse:
    try:
        approval = repository.approve_profile_release(
            release_sha256,
            authenticated_principal=principal.actor_id,
        )
    except ProfileReleaseUnknownOutcomeError as error:
        raise _profile_release_unknown(error) from error
    except ProfileReleaseRetryableAbortError as error:
        raise _profile_release_retryable_abort(error) from error
    except DBAPIError as error:
        if isinstance(error, IntegrityError):
            raise _profile_release_conflict(error) from error
        unknown = ProfileReleaseUnknownOutcomeError(
            action="APPROVE",
            lookup_path=f"/internal/evaluation/profile-releases/{release_sha256}/state",
        )
        raise _profile_release_unknown(unknown) from error
    except (ValueError, ProfileReleaseReplayError) as error:
        raise _profile_release_conflict(error) from error
    return ProfileReleaseMutationResponse(
        release_sha256=approval.release_sha256,
        state=ProfileReleaseState.APPROVED_INACTIVE,
        receipt_sha256=approval.approval_sha256,
    )


@router.post(
    "/profile-releases/{release_sha256}/activate",
    response_model=ProfileReleaseMutationResponse,
    responses=_PROFILE_RELEASE_RESPONSES,
)
def activate_profile_release(
    release_sha256: Sha256,
    request: ProfileReleaseActivateRequest,
    principal: Annotated[Phase3Principal, Depends(_approver_principal)],
    repository: Annotated[EvaluationRepository, Depends(_approver_repository)],
) -> ProfileReleaseMutationResponse:
    try:
        result = repository.activate_profile_release(
            release_sha256,
            expected_current=request.expected_current_sha256,
            authenticated_principal=principal.actor_id,
            nonce=request.nonce,
        )
    except ProfileReleaseUnknownOutcomeError as error:
        raise _profile_release_unknown(error) from error
    except ProfileReleaseRetryableAbortError as error:
        raise _profile_release_retryable_abort(error) from error
    except DBAPIError as error:
        if isinstance(error, IntegrityError):
            raise _profile_release_conflict(error) from error
        nonce_sha256 = hashlib.sha256(request.nonce.encode("ascii")).hexdigest()
        unknown = ProfileReleaseUnknownOutcomeError(
            action="ACTIVATE",
            lookup_path=(
                f"/internal/evaluation/profile-releases/transition-receipts/by-nonce/{nonce_sha256}"
            ),
        )
        raise _profile_release_unknown(unknown) from error
    except (ValueError, ProfileReleaseReplayError) as error:
        raise _profile_release_conflict(error) from error
    return ProfileReleaseMutationResponse(
        release_sha256=result.receipt.release_sha256,
        state=ProfileReleaseState.ACTIVE,
        receipt_sha256=result.receipt.receipt_sha256,
        completion=result.completion.value,
    )


@router.post(
    "/profile-releases/{release_sha256}/rollback",
    response_model=ProfileReleaseMutationResponse,
    responses=_PROFILE_RELEASE_RESPONSES,
)
def rollback_profile_release(
    release_sha256: Sha256,
    request: ProfileReleaseRollbackRequest,
    principal: Annotated[Phase3Principal, Depends(_approver_principal)],
    repository: Annotated[EvaluationRepository, Depends(_approver_repository)],
) -> ProfileReleaseMutationResponse:
    try:
        result = repository.rollback_profile_release(
            release_sha256,
            expected_current=request.expected_current_sha256,
            authenticated_principal=principal.actor_id,
            reason=request.reason,
            nonce=request.nonce,
        )
    except ProfileReleaseUnknownOutcomeError as error:
        raise _profile_release_unknown(error) from error
    except ProfileReleaseRetryableAbortError as error:
        raise _profile_release_retryable_abort(error) from error
    except DBAPIError as error:
        if isinstance(error, IntegrityError):
            raise _profile_release_conflict(error) from error
        nonce_sha256 = hashlib.sha256(request.nonce.encode("ascii")).hexdigest()
        unknown = ProfileReleaseUnknownOutcomeError(
            action="ROLLBACK",
            lookup_path=(
                f"/internal/evaluation/profile-releases/transition-receipts/by-nonce/{nonce_sha256}"
            ),
        )
        raise _profile_release_unknown(unknown) from error
    except (ValueError, ProfileReleaseReplayError) as error:
        raise _profile_release_conflict(error) from error
    return ProfileReleaseMutationResponse(
        release_sha256=result.receipt.release_sha256,
        state=ProfileReleaseState.ACTIVE,
        receipt_sha256=result.receipt.receipt_sha256,
        completion=result.completion.value,
    )


@router.post(
    "/profile-releases/sessions/{session_ref}/pin",
    response_model=ProfileReleasePinResponse,
    status_code=status.HTTP_201_CREATED,
    responses=_PROFILE_RELEASE_RESPONSES,
)
def pin_profile_release_session(
    session_ref: str,
    principal: Annotated[Phase3Principal, Depends(_builder_principal)],
    repository: Annotated[EvaluationRepository, Depends(_builder_repository)],
) -> ProfileReleasePinResponse:
    try:
        pin = repository.pin_profile_release_session(session_ref)
    except (ValueError, ProfileReleaseReplayError) as error:
        raise _profile_release_conflict(error) from error
    return ProfileReleasePinResponse(
        release_sha256=pin.release_sha256,
        pin_sha256=cast(str, pin.pin_sha256),
    )


@router.get(
    "/profile-releases/sessions/{session_ref}/pin",
    response_model=ProfileReleaseSessionPinProjection,
    responses=_PROFILE_RELEASE_READ_RESPONSES,
)
def get_profile_release_session_pin(
    session_ref: str,
    principal: Annotated[Phase3Principal, Depends(_profile_release_reader_principal)],
    repository: Annotated[EvaluationRepository, Depends(_profile_release_reader_repository)],
) -> ProfileReleaseSessionPinProjection:
    del principal
    try:
        projection = repository.get_profile_release_session_pin(session_ref)
    except DBAPIError as error:
        raise _profile_release_read_unavailable(error) from error
    except (ValueError, ProfileReleaseReplayError) as error:
        raise _profile_release_conflict(error) from error
    if projection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="profile release session pin not found",
        )
    return projection


@router.post(
    "/profile-releases/results/{result_ref}/pin",
    response_model=ProfileReleasePinResponse,
    status_code=status.HTTP_201_CREATED,
    responses=_PROFILE_RELEASE_RESPONSES,
)
def pin_profile_release_result(
    result_ref: str,
    principal: Annotated[Phase3Principal, Depends(_builder_principal)],
    repository: Annotated[EvaluationRepository, Depends(_builder_repository)],
) -> ProfileReleasePinResponse:
    try:
        pin = repository.pin_profile_release_result(result_ref)
    except (ValueError, ProfileReleaseReplayError) as error:
        raise _profile_release_conflict(error) from error
    return ProfileReleasePinResponse(
        release_sha256=pin.release_sha256,
        pin_sha256=cast(str, pin.pin_sha256),
    )


@router.get(
    "/daily-glm-refresh/status",
    response_model=DailyRefreshStatusProjection,
)
def get_daily_glm_refresh_status(
    principal: Annotated[Phase3Principal, Depends(_profile_release_reader_principal)],
    reader: Annotated[
        DailyReleaseOverlayReader,
        Depends(get_daily_release_overlay_reader),
    ],
) -> DailyRefreshStatusProjection:
    del principal
    try:
        record = reader.status()
    except DailyRefreshStoreError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="daily GLM refresh status unavailable",
        ) from error
    scheduled = next_run_at(datetime.now(UTC))
    if record is None:
        return DailyRefreshStatusProjection(
            run_date=None,
            status=None,
            changed_count=0,
            failed_count=0,
            call_count=0,
            active_release_sha256=None,
            next_run_at=scheduled,
        )
    return DailyRefreshStatusProjection(
        run_date=record.run_date,
        status=record.status,
        changed_count=record.changed_count,
        failed_count=record.failed_count,
        call_count=record.call_count,
        active_release_sha256=record.active_release_sha256,
        next_run_at=scheduled,
        safe_reason=record.safe_reason,
    )


@router.post("/freeze", response_model=LabelFreezeReceipt)
def freeze_labels(
    request: LabelFreezeRequest,
    principal: Annotated[Phase3Principal, Depends(get_phase3_principal)],
    repository: Annotated[EvaluationRepository, Depends(get_evaluation_repository)],
) -> LabelFreezeReceipt:
    _require_builder(principal)
    output = os.environ.get("ITDA_PHASE3_LABEL_FREEZE_OUTPUT")
    if not output:
        raise RuntimeError("Phase 3 label freeze output is not configured")
    export = repository.get_label_export(request.export_sha256)
    if export is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="adjudicated label export not found",
        )
    try:
        return publish_label_freeze(
            Path(output),
            export,
            rubric_sha256=request.rubric_sha256,
            source_root_sha256=request.source_root_sha256,
            dev_lineage_sha256=request.dev_lineage_sha256,
        )
    except LabelExportBlocked as error:
        raise _conflict(error) from error


__all__ = ["router"]
