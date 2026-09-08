"""Strict review-only contracts for the six locked PREVIEW candidates."""

from __future__ import annotations

import hashlib
import math
import os
import re
from base64 import b64decode, b64encode
from binascii import Error as Base64Error
from collections.abc import Container
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath
from stat import S_ISDIR, S_ISREG
from typing import Annotated, Literal, Self

from pydantic import (
    Field,
    SerializerFunctionWrapHandler,
    ValidationError,
    field_validator,
    model_serializer,
    model_validator,
)

from itda.contracts.base import (
    AssessmentStatus,
    DataSplit,
    Sha256,
    StableId,
    StrictContract,
    Version,
    require_utc,
)
from itda.contracts.provenance import (
    MAX_PROVIDER_RAW_BASE64_CHARS,
    AssetUsageStatus,
    SourceProvider,
    extract_provider_modifiedtime,
    extract_upstream_rights,
    parse_provider_json_bytes,
    validate_provider_raw_bytes,
)

CHECK_RESOLVED = 0
CHECK_MALFORMED = 1
CHECK_UNRESOLVED = 2
BLOCKED_RIGHTS_STATUS = AssetUsageStatus.BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW.value
LOCKED_PREVIEW_CANDIDATES = (
    "불국사",
    "석굴암",
    "첨성대",
    "동궁과 월지",
    "대릉원 일원",
    "황리단길",
)
_REVIEW_ARTIFACT_NAMES = frozenset(
    {
        "raw-provider-bundle.redacted.json",
        "candidate-review.json",
        "candidate-review.md",
        "review-manifest.json",
    }
)
_APPROVED_REVIEW_ARTIFACT_NAMES = _REVIEW_ARTIFACT_NAMES | {"APPROVAL.md"}


class ReviewArtifactStatus(StrEnum):
    REVIEW_ONLY = "REVIEW_ONLY"


class CandidateResolutionStatus(StrEnum):
    RESOLVED = "RESOLVED"
    UNRESOLVED = "UNRESOLVED"


class ApprovalStatus(StrEnum):
    APPROVED = "APPROVED"


class RightsDispositionStatus(StrEnum):
    USABLE = "USABLE"
    ORIGINAL_DISPLAY_ONLY = "ORIGINAL_DISPLAY_ONLY"


class RightsScope(StrEnum):
    TOUR_METADATA_TEXT = "TOUR_METADATA_TEXT"
    ODII_VOICE_SCRIPT_PHOTO = "ODII_VOICE_SCRIPT_PHOTO"
    REPRESENTATIVE_IMAGE = "REPRESENTATIVE_IMAGE"
    DETAIL_IMAGE = "DETAIL_IMAGE"


class DatasetRightsDisposition(StrictContract):
    provider: SourceProvider
    dataset_name: Annotated[str, Field(strict=True, min_length=1, max_length=240)]
    dataset_id: Annotated[str, Field(strict=True, min_length=1, max_length=80)]
    official_license_url: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    license_code: Annotated[str, Field(strict=True, min_length=1, max_length=80)]
    scope: RightsScope
    source_id: StableId
    endpoint: Annotated[str, Field(strict=True, min_length=1, max_length=300)]
    retrieved_at: datetime
    raw_response_sha256: Sha256
    attribution_required: Annotated[bool, Field(strict=True)]
    commercial_use_allowed: Annotated[bool, Field(strict=True)]
    derivatives_allowed: Annotated[bool, Field(strict=True)]
    provenance_retained: Literal[True]

    @field_validator("retrieved_at")
    @classmethod
    def retrieved_at_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="retrieved_at")

    @field_validator("official_license_url")
    @classmethod
    def official_license_url_must_be_https(cls, value: str) -> str:
        if not value.startswith("https://www.data.go.kr/data/") or not value.endswith(
            "/openapi.do"
        ):
            raise ValueError("official_license_url must identify a data.go.kr dataset page")
        return value


class ImageRightsDisposition(StrictContract):
    source_id: StableId
    asset_id: StableId
    source_url: Annotated[str, Field(strict=True, min_length=1, max_length=1_000)]
    endpoint: Literal["KorService2/detailCommon2", "KorService2/detailImage2"]
    scope: Literal[RightsScope.REPRESENTATIVE_IMAGE, RightsScope.DETAIL_IMAGE]
    cpyrht_div_cd: Literal["Type1", "Type3"]
    status: RightsDispositionStatus
    retrieved_at: datetime
    raw_response_sha256: Sha256
    modifiedtime: Annotated[str | None, Field(strict=True, min_length=1, max_length=80)] = None
    attribution_required: Literal[True]
    commercial_use_allowed: Literal[True]
    derivatives_allowed: Annotated[bool, Field(strict=True)]
    transform_allowed: Annotated[bool, Field(strict=True)]
    model_input_allowed: Annotated[bool, Field(strict=True)]
    normalized_asset_allowed: Annotated[bool, Field(strict=True)]

    @field_validator("retrieved_at")
    @classmethod
    def retrieved_at_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="retrieved_at")

    @field_validator("source_url")
    @classmethod
    def source_url_must_be_http(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("image source_url must be an absolute HTTP(S) URL")
        return value

    @model_validator(mode="after")
    def validate_type_permissions(self) -> Self:
        allowed = (
            self.derivatives_allowed,
            self.transform_allowed,
            self.model_input_allowed,
            self.normalized_asset_allowed,
        )
        if self.cpyrht_div_cd == "Type1":
            if self.status is not RightsDispositionStatus.USABLE or not all(allowed):
                raise ValueError("Type1 image must be usable with attribution")
        elif self.status is not RightsDispositionStatus.ORIGINAL_DISPLAY_ONLY or any(allowed):
            raise ValueError("Type3 image must remain original-display-only")
        return self


class SelectedOdiiStoryIdentity(StrictContract):
    tid: StableId
    tlid: StableId
    stid: StableId
    stlid: StableId
    title: Annotated[str, Field(strict=True, min_length=1, max_length=240)]
    raw_response_sha256: Sha256


class ApprovedPreviewIdentity(StrictContract):
    place_id: StableId
    name_ko: Annotated[str, Field(strict=True, min_length=1, max_length=240)]
    tour_source_id: StableId
    selected_odii_story: SelectedOdiiStoryIdentity


class CandidateRightsDisposition(StrictContract):
    place_id: StableId
    overall_status: Literal["USABLE_WITH_RESTRICTIONS"]
    tour_metadata_text: DatasetRightsDisposition
    odii_content: DatasetRightsDisposition
    selected_odii_story: SelectedOdiiStoryIdentity | None = None
    representative_image: ImageRightsDisposition
    detail_images: tuple[ImageRightsDisposition, ...]

    @model_validator(mode="after")
    def validate_candidate_rights(self) -> Self:
        if (
            self.tour_metadata_text.provider is not SourceProvider.TOUR_API
            or self.tour_metadata_text.scope is not RightsScope.TOUR_METADATA_TEXT
            or self.odii_content.provider is not SourceProvider.ODII
            or self.odii_content.scope is not RightsScope.ODII_VOICE_SCRIPT_PHOTO
            or self.odii_content.license_code != "Type0"
            or self.representative_image.scope is not RightsScope.REPRESENTATIVE_IMAGE
            or not self.detail_images
            or any(image.scope is not RightsScope.DETAIL_IMAGE for image in self.detail_images)
            or len({image.asset_id for image in self.detail_images}) != len(self.detail_images)
        ):
            raise ValueError("candidate rights disposition is inconsistent")
        if self.selected_odii_story is not None:
            selected = self.selected_odii_story
            if (
                self.odii_content.source_id != f"{selected.tid}/{selected.tlid}"
                or self.odii_content.raw_response_sha256 != selected.raw_response_sha256
            ):
                raise ValueError("selected Odii story identity is not response-bound")
        return self


class RightsReviewDecision(StrictContract):
    policy_version: Literal[
        "official-public-data-contest-v1",
        "official-public-data-contest-v2",
    ]
    source_review_manifest_sha256: Sha256
    candidates: tuple[
        CandidateRightsDisposition,
        CandidateRightsDisposition,
        CandidateRightsDisposition,
        CandidateRightsDisposition,
        CandidateRightsDisposition,
        CandidateRightsDisposition,
    ]

    @model_validator(mode="after")
    def validate_locked_rights_order(self) -> Self:
        if tuple(candidate.place_id for candidate in self.candidates) != tuple(
            f"preview:{index}" for index in range(1, 7)
        ):
            raise ValueError("rights review must cover the locked six candidate IDs in order")
        selected_stories = tuple(candidate.selected_odii_story for candidate in self.candidates)
        if self.policy_version == "official-public-data-contest-v1":
            if any(story is not None for story in selected_stories):
                raise ValueError("legacy rights policy must omit selected Odii story identity")
        elif any(story is None for story in selected_stories):
            raise ValueError("current rights policy requires selected Odii story identity")
        return self


class CandidateEvidence(StrictContract):
    provider: SourceProvider
    source_id: StableId | None
    endpoint: Annotated[str, Field(strict=True, min_length=1, max_length=300)]
    request_scope: dict[
        Annotated[str, Field(strict=True, min_length=1, max_length=100)],
        Annotated[str, Field(strict=True, max_length=500)],
    ]
    retrieved_at: datetime
    http_status: Annotated[int, Field(strict=True, ge=100, le=599)]
    raw_response_sha256: Sha256
    modifiedtime: Annotated[str | None, Field(strict=True, min_length=1, max_length=80)] = None
    upstream_rights: tuple[dict[str, str], ...]
    asset_usage_status: AssetUsageStatus
    unresolved_reason: Annotated[str | None, Field(strict=True, min_length=1, max_length=500)] = (
        None
    )

    @field_validator("retrieved_at")
    @classmethod
    def retrieved_at_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="retrieved_at")

    @field_validator("request_scope")
    @classmethod
    def request_scope_must_be_secret_free(cls, value: dict[str, str]) -> dict[str, str]:
        forbidden = ("servicekey", "api_key", "apikey", "token", "secret", "authorization")
        if any(part in key.casefold() for key in value for part in forbidden):
            raise ValueError("request_scope must exclude credentials")
        return value

    @model_validator(mode="after")
    def validate_resolution_and_rights(self) -> Self:
        if self.source_id is None and self.unresolved_reason is None:
            raise ValueError("missing source_id requires unresolved_reason")
        if self.source_id is not None and self.unresolved_reason is not None:
            raise ValueError("resolved evidence must not include unresolved_reason")
        if self.asset_usage_status is not AssetUsageStatus.BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW:
            raise ValueError("Phase 1 candidate evidence must remain blocked for rights review")
        return self


class CandidateReviewItem(StrictContract):
    place_id: StableId
    name_ko: Annotated[str, Field(strict=True, min_length=1, max_length=240)]
    address_ko: Annotated[str | None, Field(strict=True, min_length=1, max_length=500)] = None
    longitude: Annotated[float | None, Field(strict=True, ge=-180, le=180)] = None
    latitude: Annotated[float | None, Field(strict=True, ge=-90, le=90)] = None
    split: DataSplit
    assessment_status: AssessmentStatus
    resolution_status: CandidateResolutionStatus
    evidence: tuple[CandidateEvidence, CandidateEvidence]

    @model_validator(mode="after")
    def validate_candidate_lifecycle(self) -> Self:
        if self.split is not DataSplit.PREVIEW:
            raise ValueError("candidate review is PREVIEW-only")
        if self.assessment_status is not AssessmentStatus.NOT_SCORED:
            raise ValueError("candidate review must remain NOT_SCORED")
        providers = tuple(item.provider for item in self.evidence)
        if providers != (SourceProvider.TOUR_API, SourceProvider.ODII):
            raise ValueError("candidate requires TOUR_API then ODII evidence")
        fully_resolved = all(item.source_id is not None for item in self.evidence)
        if fully_resolved != (self.resolution_status is CandidateResolutionStatus.RESOLVED):
            raise ValueError("resolution_status must match provider evidence")
        return self


class CandidateReview(StrictContract):
    schema_version: Literal["candidate-review-v1", "candidate-review-v2"]
    artifact_status: ReviewArtifactStatus
    bundle_path: Annotated[str, Field(strict=True, min_length=1, max_length=300)]
    redacted_bundle_sha256: Sha256
    candidates: tuple[
        CandidateReviewItem,
        CandidateReviewItem,
        CandidateReviewItem,
        CandidateReviewItem,
        CandidateReviewItem,
        CandidateReviewItem,
    ]
    rights_review: RightsReviewDecision | None = None

    @model_serializer(mode="wrap")
    def serialize_schema_shape(
        self,
        handler: SerializerFunctionWrapHandler,
    ) -> dict[str, object]:
        payload: dict[str, object] = handler(self)
        if self.schema_version == "candidate-review-v1":
            payload.pop("rights_review", None)
        return payload

    @field_validator("bundle_path")
    @classmethod
    def bundle_path_must_be_safe_relative(cls, value: str) -> str:
        candidate = PurePosixPath(value)
        if candidate.is_absolute() or ".." in candidate.parts or not candidate.name:
            raise ValueError("bundle_path must be a safe relative path")
        return value

    @model_validator(mode="after")
    def validate_locked_candidate_set(self) -> Self:
        names = tuple(candidate.name_ko for candidate in self.candidates)
        if names != LOCKED_PREVIEW_CANDIDATES:
            raise ValueError("candidate names and order must match the locked six-place set")
        place_ids = tuple(candidate.place_id for candidate in self.candidates)
        if len(set(place_ids)) != len(place_ids):
            raise ValueError("candidate place_id values must be unique")
        if (
            self.schema_version == "candidate-review-v1"
            and "rights_review" in self.model_fields_set
        ):
            raise ValueError("candidate-review-v1 must omit rights_review")
        if (self.schema_version == "candidate-review-v2") != (self.rights_review is not None):
            raise ValueError(
                "schema_version candidate-review-v2 requires the explicit rights review decision"
            )
        return self


class RawProviderBundleRow(StrictContract):
    candidate_place_id: StableId
    provider: SourceProvider
    endpoint: Annotated[str, Field(strict=True, min_length=1, max_length=300)]
    request_scope: dict[
        Annotated[str, Field(strict=True, min_length=1, max_length=100)],
        Annotated[str, Field(strict=True, max_length=500)],
    ]
    source_id: StableId | None
    retrieved_at: datetime
    http_status: Annotated[int, Field(strict=True, ge=100, le=599)]
    raw_response_sha256: Sha256
    raw_body_base64: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=MAX_PROVIDER_RAW_BASE64_CHARS),
    ]
    modifiedtime: Annotated[str | None, Field(strict=True, min_length=1, max_length=80)] = None
    rights: tuple[dict[str, str], ...]
    asset_usage_status: AssetUsageStatus

    @field_validator("retrieved_at")
    @classmethod
    def retrieved_at_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="retrieved_at")

    @field_validator("request_scope")
    @classmethod
    def request_scope_must_be_secret_free(cls, value: dict[str, str]) -> dict[str, str]:
        forbidden = ("servicekey", "api_key", "apikey", "token", "secret", "authorization")
        if any(part in key.casefold() for key in value for part in forbidden):
            raise ValueError("provider bundle request_scope must exclude credentials")
        return value

    @model_validator(mode="after")
    def raw_body_must_match_hash(self) -> Self:
        try:
            raw_body = b64decode(self.raw_body_base64, validate=True)
        except (Base64Error, ValueError) as exc:
            raise ValueError("raw_body_base64 must be strict base64") from exc
        validate_provider_raw_bytes(raw_body)
        if b64encode(raw_body).decode("ascii") != self.raw_body_base64:
            raise ValueError("raw_body_base64 must use canonical standard base64")
        if sha256_bytes(raw_body) != self.raw_response_sha256:
            raise ValueError("raw response hash does not match exact base64 body")
        payload = parse_provider_json_bytes(raw_body)
        if extract_provider_modifiedtime(payload) != self.modifiedtime:
            raise ValueError("modifiedtime projection does not match exact raw response body")
        if extract_upstream_rights(payload) != self.rights:
            raise ValueError("rights projection does not match exact raw response body")
        return self


class RawProviderBundle(StrictContract):
    schema_version: Version
    redacted: Annotated[bool, Field(strict=True)]
    rows: tuple[RawProviderBundleRow, ...]

    @model_validator(mode="after")
    def validate_exact_shape(self) -> Self:
        if self.schema_version != "provider-bundle-v1" or self.redacted is not True:
            raise ValueError("provider bundle version or redaction marker is invalid")
        if not 12 <= len(self.rows) <= 30:
            raise ValueError("provider bundle must preserve twelve to thirty response rows")
        locked_ids = {f"preview:{index}" for index in range(1, 7)}
        if {row.candidate_place_id for row in self.rows} != locked_ids:
            raise ValueError("provider bundle rows must cover the exact six candidate IDs")
        return self


class FreezeApproval(StrictContract):
    schema_version: Literal["preview-freeze-approval-v1"]
    approval_signal: Literal["approved-six-preview"]
    status: ApprovalStatus
    canonical_candidate_review_sha256: Sha256
    canonical_candidate_review_markdown_sha256: Sha256
    canonical_source_lock_sha256: Sha256
    approved_redacted_provider_bundle_sha256: Sha256
    approved_review_manifest_sha256: Sha256
    approved_candidate_identities: tuple[
        ApprovedPreviewIdentity,
        ApprovedPreviewIdentity,
        ApprovedPreviewIdentity,
        ApprovedPreviewIdentity,
        ApprovedPreviewIdentity,
        ApprovedPreviewIdentity,
    ]
    rights_acknowledgement_version: Literal["official-public-data-contest-v2"]
    reviewer: Annotated[str, Field(strict=True, min_length=1, max_length=200)]
    approved_at: datetime

    @model_validator(mode="after")
    def validate_locked_approved_identities(self) -> Self:
        if (
            tuple(item.place_id for item in self.approved_candidate_identities)
            != tuple(f"preview:{index}" for index in range(1, 7))
            or tuple(item.name_ko for item in self.approved_candidate_identities)
            != LOCKED_PREVIEW_CANDIDATES
        ):
            raise ValueError("approved identities must preserve the locked six-place order")
        return self

    @field_validator("approved_at")
    @classmethod
    def approved_at_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="approved_at")


class ReviewManifest(StrictContract):
    schema_version: Version
    artifact_status: ReviewArtifactStatus
    redacted_provider_bundle_path: Annotated[str, Field(strict=True, min_length=1, max_length=100)]
    redacted_provider_bundle_sha256: Sha256
    candidate_review_path: Annotated[str, Field(strict=True, min_length=1, max_length=100)]
    candidate_review_sha256: Sha256
    candidate_review_markdown_path: Annotated[str, Field(strict=True, min_length=1, max_length=100)]
    candidate_review_markdown_sha256: Sha256
    candidate_names: tuple[str, str, str, str, str, str]
    split: DataSplit
    assessment_status: AssessmentStatus

    @model_validator(mode="after")
    def validate_exact_review_boundary(self) -> Self:
        if self.schema_version != "review-manifest-v1":
            raise ValueError("review manifest version is invalid")
        if self.artifact_status is not ReviewArtifactStatus.REVIEW_ONLY:
            raise ValueError("review manifest must remain REVIEW_ONLY")
        if (
            self.redacted_provider_bundle_path != "raw-provider-bundle.redacted.json"
            or self.candidate_review_path != "candidate-review.json"
            or self.candidate_review_markdown_path != "candidate-review.md"
        ):
            raise ValueError("review manifest paths must match the exact review artifact set")
        if self.candidate_names != LOCKED_PREVIEW_CANDIDATES:
            raise ValueError("review manifest identities must match the locked six-place order")
        if self.split is not DataSplit.PREVIEW:
            raise ValueError("review manifest is PREVIEW-only")
        if self.assessment_status is not AssessmentStatus.NOT_SCORED:
            raise ValueError("review manifest must remain NOT_SCORED")
        return self


class PreviewSourceLock(StrictContract):
    """Git-reviewed trust anchor for the immutable PREVIEW v1 source snapshot."""

    schema_version: Literal["preview-source-lock-v1"]
    data_version: Literal["preview-v1"]
    source_candidate_review_path: Literal["candidate-review.json"]
    source_candidate_review_sha256: Sha256
    source_candidate_review_markdown_path: Literal["candidate-review.md"]
    source_candidate_review_markdown_sha256: Sha256
    source_redacted_provider_bundle_path: Literal["raw-provider-bundle.redacted.json"]
    source_redacted_provider_bundle_sha256: Sha256
    source_review_manifest_path: Literal["review-manifest.json"]
    source_review_manifest_sha256: Sha256
    source_candidate_schema_version: Literal["candidate-review-v1"]
    source_manifest_schema_version: Literal["review-manifest-v1"]


@dataclass(frozen=True, slots=True)
class PreviewSourceLockSnapshot:
    lock: PreviewSourceLock
    payload: bytes


@dataclass(frozen=True, slots=True)
class ReviewCheckResult:
    exit_code: int
    review: CandidateReview | None
    bundle_path: Path | None
    reason: str


@dataclass(frozen=True, slots=True)
class ReviewManifestCheckResult:
    exit_code: int
    manifest: ReviewManifest | None
    review: CandidateReview | None
    bundle_path: Path | None
    reason: str


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def canonical_json_bytes(payload: object) -> bytes:
    import json

    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        + b"\n"
    )


def _require_secure_descriptor_read_capabilities() -> tuple[int, int]:
    """Return required flags only when secure descriptor-relative reads are supported."""

    missing: list[str] = []
    directory_flag = getattr(os, "O_DIRECTORY", None)
    nofollow_flag = getattr(os, "O_NOFOLLOW", None)
    if not isinstance(directory_flag, int) or directory_flag == 0:
        missing.append("O_DIRECTORY")
    if not isinstance(nofollow_flag, int) or nofollow_flag == 0:
        missing.append("O_NOFOLLOW")

    supports_dir_fd: Container[object] = getattr(os, "supports_dir_fd", ())
    supports_follow_symlinks: Container[object] = getattr(os, "supports_follow_symlinks", ())
    if os.open not in supports_dir_fd:
        missing.append("os.open(dir_fd)")
    if os.stat not in supports_dir_fd:
        missing.append("os.stat(dir_fd)")
    if os.stat not in supports_follow_symlinks:
        missing.append("os.stat(follow_symlinks=False)")
    if missing:
        raise ValueError(
            "platform lacks required secure descriptor read capabilities: " + ", ".join(missing)
        )
    assert isinstance(directory_flag, int)
    assert isinstance(nofollow_flag, int)
    return directory_flag, nofollow_flag


def _read_pinned_regular_bytes(path: Path, *, label: str) -> bytes:
    """Read one bounded regular file while pinning directory and child inode."""

    directory_flag, nofollow_flag = _require_secure_descriptor_read_capabilities()
    if path.name != "preview-v1-source-lock.json":
        raise ValueError(f"{label} must use the exact versioned artifact name")
    directory_flags = os.O_RDONLY | directory_flag | nofollow_flag
    directory_descriptor = os.open(path.parent, directory_flags)
    try:
        if not S_ISDIR(os.fstat(directory_descriptor).st_mode):
            raise ValueError(f"{label} parent must be a regular non-symlink directory")
        try:
            before = os.stat(
                path.name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            raise ValueError(f"{label} is missing") from None
        if not S_ISREG(before.st_mode) or not 0 < before.st_size <= 32_768:
            raise ValueError(f"{label} must be a bounded regular non-symlink file")
        descriptor = os.open(
            path.name,
            os.O_RDONLY | nofollow_flag,
            dir_fd=directory_descriptor,
        )
        try:
            opened = os.fstat(descriptor)
            if (
                not S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                or opened.st_size != before.st_size
            ):
                raise ValueError(f"{label} changed between stat and open")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                payload = handle.read()
            after = os.fstat(descriptor)
            if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
            ) or len(payload) != opened.st_size:
                raise ValueError(f"{label} changed while being read")
            return payload
        finally:
            os.close(descriptor)
    finally:
        os.close(directory_descriptor)


def load_preview_source_lock_snapshot(path: Path) -> PreviewSourceLockSnapshot:
    """Load the external Git-tracked source lock through a pinned descriptor."""

    try:
        payload = _read_pinned_regular_bytes(path, label="preview source lock")
        return PreviewSourceLockSnapshot(
            lock=PreviewSourceLock.model_validate_json(payload),
            payload=payload,
        )
    except (OSError, ValueError, ValidationError) as exc:
        raise ValueError(f"preview source lock is invalid: {exc}") from exc


def load_preview_source_lock(path: Path) -> PreviewSourceLock:
    """Load only the validated source-lock model for compatibility callers."""

    return load_preview_source_lock_snapshot(path).lock


def _validate_source_lock_snapshot(
    source_lock: PreviewSourceLock,
    *,
    bundle_bytes: bytes,
    candidate_bytes: bytes,
    markdown_bytes: bytes,
    manifest_bytes: bytes,
) -> None:
    """Require exact source bytes, not a self-consistent artifact-only re-sign."""

    candidate = CandidateReview.model_validate_json(candidate_bytes)
    manifest = ReviewManifest.model_validate_json(manifest_bytes)
    bundle = RawProviderBundle.model_validate_json(bundle_bytes)
    if (
        candidate.schema_version != source_lock.source_candidate_schema_version
        or candidate.rights_review is not None
        or manifest.schema_version != source_lock.source_manifest_schema_version
        or bundle.schema_version != "provider-bundle-v1"
    ):
        raise ValueError("preview source lock schema binding is invalid")
    expected = (
        (
            sha256_bytes(candidate_bytes),
            source_lock.source_candidate_review_sha256,
        ),
        (
            sha256_bytes(markdown_bytes),
            source_lock.source_candidate_review_markdown_sha256,
        ),
        (
            sha256_bytes(bundle_bytes),
            source_lock.source_redacted_provider_bundle_sha256,
        ),
        (
            sha256_bytes(manifest_bytes),
            source_lock.source_review_manifest_sha256,
        ),
    )
    if any(actual != locked for actual, locked in expected):
        raise ValueError("preview source snapshot does not match external source lock")
    if (
        manifest.candidate_review_sha256 != source_lock.source_candidate_review_sha256
        or manifest.candidate_review_markdown_sha256
        != source_lock.source_candidate_review_markdown_sha256
        or manifest.redacted_provider_bundle_sha256
        != source_lock.source_redacted_provider_bundle_sha256
    ):
        raise ValueError("preview source manifest does not match external source lock")


def _resolve_bundle_path(review_path: Path, bundle_path: str) -> Path:
    review_root = review_path.parent.resolve(strict=True)
    unresolved = review_root / bundle_path
    current = review_root
    for part in PurePosixPath(bundle_path).parts:
        current /= part
        if current.is_symlink():
            raise ValueError("bundle_path must not traverse symlinks")
    resolved = unresolved.resolve(strict=True)
    if not resolved.is_relative_to(review_root):
        raise ValueError("bundle_path escapes the review directory")
    if not resolved.is_file():
        raise ValueError("bundle_path must identify a file")
    return resolved


def check_candidate_review(
    review_path: Path,
    *,
    source_lock: PreviewSourceLock | None = None,
) -> ReviewCheckResult:
    """Validate review integrity and return the stable 0/1/2 exit partition."""

    try:
        review_bytes = review_path.read_bytes()
        review = CandidateReview.model_validate_json(review_bytes)
        bundle_path = _resolve_bundle_path(review_path, review.bundle_path)
        bundle_bytes = bundle_path.read_bytes()
        if sha256_bytes(bundle_bytes) != review.redacted_bundle_sha256:
            raise ValueError("redacted provider bundle SHA-256 mismatch")
        bundle = RawProviderBundle.model_validate_json(bundle_bytes)
        if review.rights_review is not None and source_lock is None:
            raise ValueError("preview source lock is required for rights-bearing review")
        for candidate in review.candidates:
            for evidence in candidate.evidence:
                matches = [
                    row
                    for row in bundle.rows
                    if row.candidate_place_id == candidate.place_id
                    and row.provider is evidence.provider
                    and row.endpoint == evidence.endpoint
                ]
                if len(matches) != 1:
                    raise ValueError("provider bundle must uniquely bind candidate evidence")
                row = matches[0]
                if (
                    row.request_scope != evidence.request_scope
                    or (
                        candidate.resolution_status is CandidateResolutionStatus.RESOLVED
                        and row.source_id != evidence.source_id
                    )
                    or row.retrieved_at != evidence.retrieved_at
                    or row.http_status != evidence.http_status
                    or row.raw_response_sha256 != evidence.raw_response_sha256
                    or row.modifiedtime != evidence.modifiedtime
                    or row.rights != evidence.upstream_rights
                    or row.asset_usage_status is not evidence.asset_usage_status
                ):
                    raise ValueError("provider bundle row does not bind candidate evidence")
        if review.rights_review is not None:
            source_candidate_bytes = canonical_json_bytes(
                _legacy_v1_review(review).model_dump(
                    mode="json",
                    exclude={"rights_review"},
                )
            )
            source_markdown_bytes = render_candidate_review_markdown(
                _legacy_v1_review(review),
                bundle,
            )
            source_manifest_bytes = build_review_manifest_from_bytes(
                bundle_bytes=bundle_bytes,
                candidate_bytes=source_candidate_bytes,
                markdown_bytes=source_markdown_bytes,
            )
            assert source_lock is not None
            _validate_source_lock_snapshot(
                source_lock,
                bundle_bytes=bundle_bytes,
                candidate_bytes=source_candidate_bytes,
                markdown_bytes=source_markdown_bytes,
                manifest_bytes=source_manifest_bytes,
            )
            trusted_source_manifest_sha256 = sha256_bytes(source_manifest_bytes)
            if review.rights_review.source_review_manifest_sha256 != trusted_source_manifest_sha256:
                raise ValueError(
                    "rights review source manifest SHA-256 does not match reconstructed v1"
                )
            selected_story_identities: tuple[SelectedOdiiStoryIdentity, ...] | None = None
            if review.rights_review.policy_version == "official-public-data-contest-v2":
                selected_story_identities = tuple(
                    candidate.selected_odii_story
                    for candidate in review.rights_review.candidates
                    if candidate.selected_odii_story is not None
                )
                if len(selected_story_identities) != 6:
                    raise ValueError("current rights review lacks selected Odii story identity")
            expected = build_rights_review(
                _legacy_v1_review(review),
                bundle,
                source_review_manifest_sha256=trusted_source_manifest_sha256,
                policy_version=review.rights_review.policy_version,
                selected_story_identities=selected_story_identities,
            )
            if expected.rights_review != review.rights_review:
                raise ValueError("rights review does not match selected provider assets")
        elif source_lock is not None:
            source_markdown_bytes = render_candidate_review_markdown(review, bundle)
            source_manifest_bytes = build_review_manifest_from_bytes(
                bundle_bytes=bundle_bytes,
                candidate_bytes=review_bytes,
                markdown_bytes=source_markdown_bytes,
            )
            _validate_source_lock_snapshot(
                source_lock,
                bundle_bytes=bundle_bytes,
                candidate_bytes=review_bytes,
                markdown_bytes=source_markdown_bytes,
                manifest_bytes=source_manifest_bytes,
            )
    except (OSError, ValueError, ValidationError) as exc:
        return ReviewCheckResult(CHECK_MALFORMED, None, None, str(exc))

    unresolved = any(
        candidate.resolution_status is CandidateResolutionStatus.UNRESOLVED
        for candidate in review.candidates
    )
    if unresolved:
        return ReviewCheckResult(CHECK_UNRESOLVED, review, bundle_path, "unresolved evidence")
    return ReviewCheckResult(CHECK_RESOLVED, review, bundle_path, "resolved")


def render_candidate_review_markdown(
    review: CandidateReview, bundle: RawProviderBundle | None = None
) -> bytes:
    selected_theme_pair_mode = _is_selected_multi_story_theme_pair_review(review, bundle)
    current_story_policy = (
        review.rights_review is not None
        and review.rights_review.policy_version == "official-public-data-contest-v2"
    )
    odii_headers = (
        "Odii request pair (tid/tlid) | Canonical Odii theme pair (tid/tlid)"
        if selected_theme_pair_mode
        else "Odii tid/tlid | Odii story ID"
    )
    lines = [
        "# IT-DA six-place PREVIEW review",
        "",
        "Status: PREVIEW / NOT_SCORED",
        "",
        f"| # | 장소 | 주소 | 좌표 | TourAPI ID | {odii_headers} | 권리 상태 | 해소 상태 |",
        "|---:|---|---|---|---|---|---|---|---|",
    ]
    for index, candidate in enumerate(review.candidates, start=1):
        tour, odii = candidate.evidence
        coordinates = (
            f"{candidate.longitude:.6f}, {candidate.latitude:.6f}"
            if candidate.longitude is not None and candidate.latitude is not None
            else "UNRESOLVED"
        )
        lines.append(
            "| "
            + " | ".join(
                (
                    str(index),
                    candidate.name_ko,
                    candidate.address_ko or "UNRESOLVED",
                    coordinates,
                    tour.source_id or "UNRESOLVED",
                    (
                        f"{odii.request_scope.get('tid', 'UNRESOLVED')}/"
                        f"{odii.request_scope.get('tlid', 'UNRESOLVED')}"
                    ),
                    odii.source_id or "UNRESOLVED",
                    BLOCKED_RIGHTS_STATUS,
                    candidate.resolution_status.value,
                )
            )
            + " |"
        )
    lines.extend(
        (
            "",
            (
                "The provider table below preserves the conservative capture-time state. "
                "The reviewed disposition table is authoritative for candidate and asset use."
                if review.rights_review is not None
                else "All Type3 or ambiguous assets are BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW "
                "and excluded from transform, model, score, UI, and demo."
            ),
            "",
        )
    )
    if review.rights_review is not None:
        lines.extend(("## Reviewed rights disposition", ""))
        if current_story_policy:
            lines.extend(
                (
                    "| 장소 | Selected Odii theme (tid/tlid) | "
                    "Selected Odii story (stid/stlid) | 선택 story 제목 | "
                    "TourAPI metadata/text | Odii voice/script/photo | 대표 이미지 | "
                    "Type1 detail images | 최종 상태 |",
                    "|---|---|---|---|---|---|---|---:|---|",
                )
            )
        else:
            lines.extend(
                (
                    "| 장소 | TourAPI metadata/text | Odii voice/script/photo | 대표 이미지 | "
                    "Type1 detail images | 최종 상태 |",
                    "|---|---|---|---|---:|---|",
                )
            )
        for candidate, rights in zip(
            review.candidates, review.rights_review.candidates, strict=True
        ):
            representative = (
                "Type3 ORIGINAL_DISPLAY_ONLY (no transform/model/normalized asset)"
                if rights.representative_image.cpyrht_div_cd == "Type3"
                else "Type1 USABLE_WITH_ATTRIBUTION"
            )
            selected_story_cells: tuple[str, ...] = ()
            if current_story_policy:
                selected_story = rights.selected_odii_story
                assert selected_story is not None
                selected_story_cells = (
                    f"{selected_story.tid}/{selected_story.tlid}",
                    f"{selected_story.stid}/{selected_story.stlid}",
                    selected_story.title,
                )
            lines.append(
                "| "
                + " | ".join(
                    (
                        candidate.name_ko,
                        *selected_story_cells,
                        rights.tour_metadata_text.license_code,
                        f"{rights.odii_content.license_code} inherited dataset grant",
                        representative,
                        str(len(rights.detail_images)),
                        rights.overall_status,
                    )
                )
                + " |"
            )
        if current_story_policy:
            lines.extend(
                (
                    "",
                    "Policy v2 pins each selected Odii story by tid/tlid/stid/stlid/title and "
                    "its bound response SHA-256. The candidate JSON, external source lock, "
                    "and provider provenance retain that binding.",
                    "",
                    "Same-theme sibling storyBasedList rows are evidence only and never affect "
                    "selected-story rights.",
                )
            )
        lines.extend(
            (
                "",
                "searchKeyword2 alternatives are discovery evidence only; their image-right "
                "markers are not aggregated into the locked selected candidate.",
                "",
                "modifiedtime=UNRESOLVED remains a freshness gap, not a license blocker. "
                "Provider, dataset ID, source IDs, retrieved_at, and response SHA-256 "
                "are retained.",
                "",
            )
        )
    if selected_theme_pair_mode and not current_story_policy:
        lines.extend(
            (
                "Canonical Odii identity is the selected theme pair (tid/tlid); "
                "storyBasedList may preserve multiple subordinate story rows as evidence and "
                "does not imply one story ID.",
                "",
            )
        )
    if bundle is not None:
        lines.extend(
            (
                "## Provider response provenance",
                "",
                "| 장소 ID | provider | endpoint | source ID | request scope | "
                "retrieved UTC | HTTP | response SHA-256 | modifiedtime | rights | asset state |",
                "|---|---|---|---|---|---|---:|---|---|---|---|",
            )
        )
        for row in bundle.rows:
            scope = canonical_json_bytes(row.request_scope).decode("utf-8").strip()
            rights_json = canonical_json_bytes(list(row.rights)).decode("utf-8").strip()
            lines.append(
                "| "
                + " | ".join(
                    (
                        row.candidate_place_id,
                        row.provider.value,
                        row.endpoint,
                        row.source_id or "UNRESOLVED",
                        scope.replace("|", "&#124;"),
                        row.retrieved_at.isoformat().replace("+00:00", "Z"),
                        str(row.http_status),
                        row.raw_response_sha256,
                        row.modifiedtime or "UNRESOLVED",
                        rights_json.replace("|", "&#124;"),
                        row.asset_usage_status.value,
                    )
                )
                + " |"
            )
        lines.append("")
    return "\n".join(lines).encode("utf-8")


def _provider_item_rows(payload: object) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    if isinstance(payload, dict):
        item = payload.get("item")
        if isinstance(item, dict):
            rows.append(item)
        elif isinstance(item, list):
            rows.extend(row for row in item if isinstance(row, dict))
        for child in payload.values():
            rows.extend(_provider_item_rows(child))
    elif isinstance(payload, list):
        for child in payload:
            rows.extend(_provider_item_rows(child))
    return rows


def _provider_field(row: dict[str, object], *names: str) -> str | None:
    for name in names:
        value = row.get(name)
        if value not in (None, ""):
            return str(value)
    return None


def _required_provider_field(
    row: dict[str, object],
    message: str,
    *names: str,
) -> str:
    value = _provider_field(row, *names)
    if value is None:
        raise ValueError(message)
    return value


def _normalized_title(value: str) -> str:
    return re.sub(r"[^0-9a-z가-힣]", "", value.casefold())


def _provider_coordinates(row: dict[str, object]) -> tuple[float, float] | None:
    x_value = _provider_field(row, "mapx", "mapX", "gpsX", "longitude", "lng")
    y_value = _provider_field(row, "mapy", "mapY", "gpsY", "latitude", "lat")
    if x_value is None or y_value is None:
        return None
    try:
        coordinates = (float(x_value), float(y_value))
    except ValueError:
        return None
    return coordinates if all(math.isfinite(value) for value in coordinates) else None


def _same_provider_coordinates(
    first: dict[str, object],
    second: dict[str, object],
    *,
    tolerance: float = 0.01,
) -> bool:
    first_coordinates = _provider_coordinates(first)
    second_coordinates = _provider_coordinates(second)
    return (
        first_coordinates is not None
        and second_coordinates is not None
        and abs(first_coordinates[0] - second_coordinates[0]) <= tolerance
        and abs(first_coordinates[1] - second_coordinates[1]) <= tolerance
    )


def _selected_odii_story_row(
    *,
    theme_payload: object,
    story_payload: object,
    tid: str,
    tlid: str,
    selected_identity: SelectedOdiiStoryIdentity | None = None,
) -> dict[str, object]:
    if selected_identity is not None:
        if selected_identity.tid != tid or selected_identity.tlid != tlid:
            raise ValueError("selected Odii story identity does not match the request pair")
        canonical_selection = _selected_odii_story_row(
            theme_payload=theme_payload,
            story_payload=story_payload,
            tid=tid,
            tlid=tlid,
        )
        if (
            _provider_field(canonical_selection, "stid", "storyId", "storyid", "sid")
            != selected_identity.stid
            or _provider_field(canonical_selection, "stlid", "storyLocationId")
            != selected_identity.stlid
        ):
            raise ValueError("selected Odii story identity does not match source selection")
        identity_matches = [
            item
            for item in _provider_item_rows(story_payload)
            if _provider_field(item, "tid", "themeId") == selected_identity.tid
            and _provider_field(item, "tlid", "themeLocationId") == selected_identity.tlid
            and _provider_field(item, "stid", "storyId", "storyid", "sid") == selected_identity.stid
            and _provider_field(item, "stlid", "storyLocationId") == selected_identity.stlid
            and _provider_field(item, "title", "name", "nameKo") == selected_identity.title
        ]
        if len(identity_matches) != 1:
            raise ValueError("selected Odii stid/stlid is not uniquely response-bound")
        return identity_matches[0]
    selected_themes = [
        item
        for item in _provider_item_rows(theme_payload)
        if _provider_field(item, "tid", "themeId") == tid
        and _provider_field(item, "tlid", "themeLocationId") == tlid
    ]
    if len(selected_themes) != 1:
        raise ValueError("Odii theme response must uniquely identify the selected candidate")
    selected_stories = [
        item
        for item in _provider_item_rows(story_payload)
        if _provider_field(item, "tid", "themeId") == tid
        and _provider_field(item, "tlid", "themeLocationId") == tlid
        and _normalized_title(_provider_field(item, "title", "name", "nameKo") or "").removeprefix(
            "경주"
        )
        == _normalized_title(
            _provider_field(selected_themes[0], "title", "name", "nameKo") or ""
        ).removeprefix("경주")
        and _same_provider_coordinates(item, selected_themes[0])
    ]
    if len(selected_stories) != 1:
        raise ValueError("Odii story response must uniquely identify the selected story")
    selected_story = selected_stories[0]
    story_id = _provider_field(selected_story, "stid", "storyId", "storyid", "sid")
    story_location_id = _provider_field(selected_story, "stlid", "storyLocationId")
    if story_id is None or story_location_id is None:
        raise ValueError("selected Odii story must bind stable stid/stlid response identity")
    return selected_story


_TOUR_DATASET_URL = "https://www.data.go.kr/data/15101578/openapi.do"
_ODII_DATASET_URL = "https://www.data.go.kr/data/15101971/openapi.do"


def _unique_bundle_row(
    bundle: RawProviderBundle, *, place_id: str, endpoint: str
) -> RawProviderBundleRow:
    matches = [
        row
        for row in bundle.rows
        if row.candidate_place_id == place_id and row.endpoint == endpoint
    ]
    if len(matches) != 1:
        raise ValueError(f"{place_id} must have exactly one {endpoint} row")
    return matches[0]


def _image_disposition(
    *,
    source_id: str,
    asset_id: str,
    source_url: str,
    endpoint: Literal["KorService2/detailCommon2", "KorService2/detailImage2"],
    scope: Literal[RightsScope.REPRESENTATIVE_IMAGE, RightsScope.DETAIL_IMAGE],
    cpyrht_div_cd: str,
    row: RawProviderBundleRow,
) -> ImageRightsDisposition:
    if cpyrht_div_cd not in {"Type1", "Type3"}:
        raise ValueError("selected image requires explicit Type1 or Type3 rights")
    normalized_code: Literal["Type1", "Type3"] = "Type1" if cpyrht_div_cd == "Type1" else "Type3"
    type1 = normalized_code == "Type1"
    return ImageRightsDisposition(
        source_id=source_id,
        asset_id=asset_id,
        source_url=source_url,
        endpoint=endpoint,
        scope=scope,
        cpyrht_div_cd=normalized_code,
        status=(
            RightsDispositionStatus.USABLE
            if type1
            else RightsDispositionStatus.ORIGINAL_DISPLAY_ONLY
        ),
        retrieved_at=row.retrieved_at,
        raw_response_sha256=row.raw_response_sha256,
        modifiedtime=row.modifiedtime,
        attribution_required=True,
        commercial_use_allowed=True,
        derivatives_allowed=type1,
        transform_allowed=type1,
        model_input_allowed=type1,
        normalized_asset_allowed=type1,
    )


def build_rights_review(
    review: CandidateReview,
    bundle: RawProviderBundle,
    *,
    source_review_manifest_sha256: str,
    policy_version: Literal[
        "official-public-data-contest-v1",
        "official-public-data-contest-v2",
    ] = "official-public-data-contest-v2",
    selected_story_identities: tuple[SelectedOdiiStoryIdentity, ...] | None = None,
) -> CandidateReview:
    """Derive the scoped official-dataset rights decision from selected v1 rows only."""

    if review.schema_version != "candidate-review-v1" or review.rights_review is not None:
        raise ValueError("rights review source must be an unclassified candidate-review-v1")
    candidate_rights: list[CandidateRightsDisposition] = []
    if selected_story_identities is not None and len(selected_story_identities) != 6:
        raise ValueError("selected Odii story identity hints must cover all six candidates")
    for candidate_index, candidate in enumerate(review.candidates):
        tour_evidence, odii_evidence = candidate.evidence
        if tour_evidence.source_id is None or odii_evidence.source_id is None:
            raise ValueError("rights review requires resolved selected identities")
        common_row = _unique_bundle_row(
            bundle,
            place_id=candidate.place_id,
            endpoint="KorService2/detailCommon2",
        )
        detail_row = _unique_bundle_row(
            bundle,
            place_id=candidate.place_id,
            endpoint="KorService2/detailImage2",
        )
        odii_theme_row = _unique_bundle_row(
            bundle,
            place_id=candidate.place_id,
            endpoint="Odii/themeSearchList",
        )
        odii_story_row = _unique_bundle_row(
            bundle,
            place_id=candidate.place_id,
            endpoint="Odii/storyBasedList",
        )
        selected_tid = odii_evidence.request_scope.get("tid")
        selected_tlid = odii_evidence.request_scope.get("tlid")
        if selected_tid is None or selected_tlid is None:
            identity_parts = odii_evidence.source_id.split("/", maxsplit=1)
            if len(identity_parts) != 2:
                raise ValueError("selected Odii identity must bind tid/tlid")
            selected_tid, selected_tlid = identity_parts
        selected_story = _selected_odii_story_row(
            theme_payload=parse_provider_json_bytes(
                b64decode(odii_theme_row.raw_body_base64, validate=True)
            ),
            story_payload=parse_provider_json_bytes(
                b64decode(odii_story_row.raw_body_base64, validate=True)
            ),
            tid=selected_tid,
            tlid=selected_tlid,
            selected_identity=(
                selected_story_identities[candidate_index]
                if selected_story_identities is not None
                else None
            ),
        )
        if extract_upstream_rights(selected_story):
            raise ValueError(
                "Odii dataset inheritance applies only when row-level rights are absent"
            )
        common_items = _provider_item_rows(
            parse_provider_json_bytes(b64decode(common_row.raw_body_base64, validate=True))
        )
        selected_common = [
            item
            for item in common_items
            if _provider_field(item, "contentid", "contentId") == tour_evidence.source_id
        ]
        if len(selected_common) != 1:
            raise ValueError("detailCommon2 must uniquely match the selected content ID")
        common = selected_common[0]
        representative_url = _provider_field(common, "firstimage", "firstImage")
        representative_rights = _provider_field(common, "cpyrhtDivCd")
        if representative_url is None or representative_rights is None:
            raise ValueError("selected representative image lacks explicit rights metadata")
        detail_items = _provider_item_rows(
            parse_provider_json_bytes(b64decode(detail_row.raw_body_base64, validate=True))
        )
        detail_images: list[ImageRightsDisposition] = []
        for item in detail_items:
            asset_id = _provider_field(item, "serialnum", "serialNum")
            source_url = _provider_field(item, "originimgurl", "originImgUrl")
            rights_code = _provider_field(item, "cpyrhtDivCd")
            if asset_id is None or source_url is None or rights_code is None:
                raise ValueError("detailImage2 asset lacks identity, URL, or explicit rights")
            detail_images.append(
                _image_disposition(
                    source_id=tour_evidence.source_id,
                    asset_id=asset_id,
                    source_url=source_url,
                    endpoint="KorService2/detailImage2",
                    scope=RightsScope.DETAIL_IMAGE,
                    cpyrht_div_cd=rights_code,
                    row=detail_row,
                )
            )
        if any(image.cpyrht_div_cd != "Type1" for image in detail_images):
            raise ValueError("current locked detailImage2 assets must all be Type1")
        candidate_rights.append(
            CandidateRightsDisposition(
                place_id=candidate.place_id,
                overall_status="USABLE_WITH_RESTRICTIONS",
                tour_metadata_text=DatasetRightsDisposition(
                    provider=SourceProvider.TOUR_API,
                    dataset_name="한국관광공사 국문 관광정보 서비스_GW",
                    dataset_id="15101578",
                    official_license_url=_TOUR_DATASET_URL,
                    license_code="OFFICIAL_DATASET_GRANT",
                    scope=RightsScope.TOUR_METADATA_TEXT,
                    source_id=tour_evidence.source_id,
                    endpoint=tour_evidence.endpoint,
                    retrieved_at=tour_evidence.retrieved_at,
                    raw_response_sha256=tour_evidence.raw_response_sha256,
                    attribution_required=False,
                    commercial_use_allowed=True,
                    derivatives_allowed=True,
                    provenance_retained=True,
                ),
                odii_content=DatasetRightsDisposition(
                    provider=SourceProvider.ODII,
                    dataset_name="한국관광공사 관광지 오디오 가이드정보_GW",
                    dataset_id="15101971",
                    official_license_url=_ODII_DATASET_URL,
                    license_code="Type0",
                    scope=RightsScope.ODII_VOICE_SCRIPT_PHOTO,
                    source_id=odii_evidence.source_id,
                    endpoint=odii_evidence.endpoint,
                    retrieved_at=odii_evidence.retrieved_at,
                    raw_response_sha256=odii_evidence.raw_response_sha256,
                    attribution_required=False,
                    commercial_use_allowed=True,
                    derivatives_allowed=True,
                    provenance_retained=True,
                ),
                selected_odii_story=(
                    SelectedOdiiStoryIdentity(
                        tid=selected_tid,
                        tlid=selected_tlid,
                        stid=_required_provider_field(
                            selected_story,
                            "selected Odii story stid is missing",
                            "stid",
                            "storyId",
                            "storyid",
                            "sid",
                        ),
                        stlid=_required_provider_field(
                            selected_story,
                            "selected Odii story stlid is missing",
                            "stlid",
                            "storyLocationId",
                        ),
                        title=_required_provider_field(
                            selected_story,
                            "selected Odii story title is missing",
                            "title",
                            "name",
                            "nameKo",
                        ),
                        raw_response_sha256=odii_story_row.raw_response_sha256,
                    )
                    if policy_version == "official-public-data-contest-v2"
                    else None
                ),
                representative_image=_image_disposition(
                    source_id=tour_evidence.source_id,
                    asset_id=f"{tour_evidence.source_id}:representative",
                    source_url=representative_url,
                    endpoint="KorService2/detailCommon2",
                    scope=RightsScope.REPRESENTATIVE_IMAGE,
                    cpyrht_div_cd=representative_rights,
                    row=common_row,
                ),
                detail_images=tuple(detail_images),
            )
        )
    payload = review.model_dump(mode="json")
    payload["schema_version"] = "candidate-review-v2"
    payload["rights_review"] = RightsReviewDecision(
        policy_version=policy_version,
        source_review_manifest_sha256=source_review_manifest_sha256,
        candidates=tuple(candidate_rights),  # type: ignore[arg-type]
    ).model_dump(mode="json")
    return CandidateReview.model_validate(payload)


def _is_selected_multi_story_theme_pair_review(
    review: CandidateReview,
    bundle: RawProviderBundle | None,
) -> bool:
    """Recognize the new selected-pair shape without changing legacy v1 bytes."""

    if bundle is None:
        return False
    has_multiple_subordinate_stories = False
    for candidate in review.candidates:
        odii = candidate.evidence[1]
        tid = odii.request_scope.get("tid")
        tlid = odii.request_scope.get("tlid")
        if tid is None or tlid is None:
            return False
        theme_pair = f"{tid}/{tlid}"
        if (
            candidate.resolution_status is not CandidateResolutionStatus.RESOLVED
            or odii.endpoint != "Odii/storyBasedList"
            or odii.source_id != theme_pair
        ):
            return False
        matching_rows = [
            row
            for row in bundle.rows
            if row.candidate_place_id == candidate.place_id
            and row.provider is SourceProvider.ODII
            and row.endpoint == "Odii/storyBasedList"
        ]
        if len(matching_rows) != 1 or matching_rows[0].source_id != theme_pair:
            return False
        raw_payload = parse_provider_json_bytes(
            b64decode(matching_rows[0].raw_body_base64, validate=True)
        )
        story_rows = _provider_item_rows(raw_payload)
        if not story_rows or any(
            _provider_field(row, "tid", "themeId") != tid
            or _provider_field(row, "tlid", "themeLocationId") != tlid
            for row in story_rows
        ):
            return False
        has_multiple_subordinate_stories |= len(story_rows) > 1
    return has_multiple_subordinate_stories


def build_review_manifest_from_bytes(
    *,
    bundle_bytes: bytes,
    candidate_bytes: bytes,
    markdown_bytes: bytes,
) -> bytes:
    """Build the manifest from one immutable in-memory exact-three snapshot."""

    review = CandidateReview.model_validate_json(candidate_bytes)
    RawProviderBundle.model_validate_json(bundle_bytes)
    manifest = ReviewManifest(
        schema_version="review-manifest-v1",
        artifact_status=ReviewArtifactStatus.REVIEW_ONLY,
        redacted_provider_bundle_path="raw-provider-bundle.redacted.json",
        redacted_provider_bundle_sha256=sha256_bytes(bundle_bytes),
        candidate_review_path="candidate-review.json",
        candidate_review_sha256=sha256_bytes(candidate_bytes),
        candidate_review_markdown_path="candidate-review.md",
        candidate_review_markdown_sha256=sha256_bytes(markdown_bytes),
        candidate_names=tuple(candidate.name_ko for candidate in review.candidates),  # type: ignore[arg-type]
        split=DataSplit.PREVIEW,
        assessment_status=AssessmentStatus.NOT_SCORED,
    )
    return canonical_json_bytes(manifest.model_dump(mode="json"))


def _legacy_v1_review(review: CandidateReview) -> CandidateReview:
    """Project v2 onto the byte-compatible v1 shape without setting rights_review."""

    payload = review.model_dump(mode="json", exclude={"rights_review"})
    payload["schema_version"] = "candidate-review-v1"
    return CandidateReview.model_validate(payload)


def _reconstructed_source_review_manifest_bytes(
    *,
    review: CandidateReview,
    bundle: RawProviderBundle,
    bundle_bytes: bytes,
) -> bytes:
    legacy = _legacy_v1_review(review)
    candidate_bytes = canonical_json_bytes(
        legacy.model_dump(mode="json", exclude={"rights_review"})
    )
    markdown_bytes = render_candidate_review_markdown(legacy, bundle)
    return build_review_manifest_from_bytes(
        bundle_bytes=bundle_bytes,
        candidate_bytes=candidate_bytes,
        markdown_bytes=markdown_bytes,
    )


def _reconstructed_source_review_manifest_sha256(
    *,
    review: CandidateReview,
    bundle: RawProviderBundle,
    bundle_bytes: bytes,
) -> str:
    return sha256_bytes(
        _reconstructed_source_review_manifest_bytes(
            review=review,
            bundle=bundle,
            bundle_bytes=bundle_bytes,
        )
    )


def build_review_manifest(review_root: Path) -> bytes:
    bundle_path = review_root / "raw-provider-bundle.redacted.json"
    candidate_path = review_root / "candidate-review.json"
    markdown_path = review_root / "candidate-review.md"
    return build_review_manifest_from_bytes(
        bundle_bytes=bundle_path.read_bytes(),
        candidate_bytes=candidate_path.read_bytes(),
        markdown_bytes=markdown_path.read_bytes(),
    )


def _resolve_manifest_artifact(
    manifest_path: Path, relative_path: str, *, expected_name: str
) -> Path:
    if relative_path != expected_name:
        raise ValueError("review artifact path does not match the exact contract")
    return _resolve_bundle_path(manifest_path, relative_path)


def _validate_exact_review_directory(
    manifest_path: Path, *, expected_names: frozenset[str]
) -> None:
    if manifest_path.name != "review-manifest.json":
        raise ValueError("review manifest path must use the exact required name")
    entries = {entry.name: entry for entry in manifest_path.parent.iterdir()}
    if frozenset(entries) != expected_names:
        raise ValueError("review directory does not contain the exact required artifacts")
    if any(not S_ISREG(entries[name].lstat().st_mode) for name in expected_names):
        raise ValueError("review artifacts must be regular non-symlink files")


def _check_review_manifest(
    manifest_path: Path,
    *,
    expected_names: frozenset[str],
    source_lock: PreviewSourceLock | None,
    source_lock_path: Path | None,
) -> ReviewManifestCheckResult:
    try:
        if source_lock is not None and source_lock_path is not None:
            raise ValueError("inject preview source lock by object or path, not both")
        if source_lock_path is not None:
            source_lock = load_preview_source_lock(source_lock_path)
        _validate_exact_review_directory(manifest_path, expected_names=expected_names)
        manifest_bytes = manifest_path.read_bytes()
        manifest = ReviewManifest.model_validate_json(manifest_bytes)
        bundle_path = _resolve_manifest_artifact(
            manifest_path,
            manifest.redacted_provider_bundle_path,
            expected_name="raw-provider-bundle.redacted.json",
        )
        candidate_path = _resolve_manifest_artifact(
            manifest_path,
            manifest.candidate_review_path,
            expected_name="candidate-review.json",
        )
        markdown_path = _resolve_manifest_artifact(
            manifest_path,
            manifest.candidate_review_markdown_path,
            expected_name="candidate-review.md",
        )
        if sha256_bytes(bundle_path.read_bytes()) != manifest.redacted_provider_bundle_sha256:
            raise ValueError("review manifest bundle SHA-256 mismatch")
        candidate_bytes = candidate_path.read_bytes()
        if sha256_bytes(candidate_bytes) != manifest.candidate_review_sha256:
            raise ValueError("review manifest candidate SHA-256 mismatch")
        markdown_bytes = markdown_path.read_bytes()
        if sha256_bytes(markdown_bytes) != manifest.candidate_review_markdown_sha256:
            raise ValueError("review manifest markdown SHA-256 mismatch")
        checked = check_candidate_review(candidate_path, source_lock=source_lock)
        if checked.exit_code == CHECK_MALFORMED or checked.review is None:
            raise ValueError(checked.reason)
        if checked.bundle_path != bundle_path:
            raise ValueError("candidate review does not bind the manifest provider bundle")
        bundle = RawProviderBundle.model_validate_json(bundle_path.read_bytes())
        if render_candidate_review_markdown(checked.review, bundle) != markdown_bytes:
            raise ValueError("candidate review markdown is not canonical")
        if checked.review.rights_review is None and source_lock is not None:
            _validate_source_lock_snapshot(
                source_lock,
                bundle_bytes=bundle_path.read_bytes(),
                candidate_bytes=candidate_bytes,
                markdown_bytes=markdown_bytes,
                manifest_bytes=manifest_bytes,
            )
        for candidate in checked.review.candidates:
            endpoints = tuple(
                row.endpoint for row in bundle.rows if row.candidate_place_id == candidate.place_id
            )
            if candidate.resolution_status is CandidateResolutionStatus.RESOLVED and endpoints != (
                "KorService2/searchKeyword2",
                "Odii/themeSearchList",
                "KorService2/detailCommon2",
                "KorService2/detailImage2",
                "Odii/storyBasedList",
            ):
                raise ValueError("resolved review must preserve all five provider responses")
        if (
            tuple(candidate.name_ko for candidate in checked.review.candidates)
            != manifest.candidate_names
        ):
            raise ValueError("review manifest identities do not match candidate review")
        if any(
            candidate.resolution_status is CandidateResolutionStatus.RESOLVED
            and (
                candidate.address_ko is None
                or candidate.longitude is None
                or candidate.latitude is None
            )
            for candidate in checked.review.candidates
        ):
            raise ValueError("resolved review candidates require address and coordinates")
        return ReviewManifestCheckResult(
            checked.exit_code,
            manifest,
            checked.review,
            bundle_path,
            checked.reason,
        )
    except (OSError, ValueError, ValidationError) as exc:
        return ReviewManifestCheckResult(CHECK_MALFORMED, None, None, None, str(exc))


def check_review_manifest(
    manifest_path: Path,
    *,
    source_lock: PreviewSourceLock | None = None,
    source_lock_path: Path | None = None,
) -> ReviewManifestCheckResult:
    """Validate the exact four-file preapproval boundary with 0/1/2 semantics."""

    return _check_review_manifest(
        manifest_path,
        expected_names=_REVIEW_ARTIFACT_NAMES,
        source_lock=source_lock,
        source_lock_path=source_lock_path,
    )


def check_approved_review_manifest(
    manifest_path: Path,
    *,
    source_lock: PreviewSourceLock | None = None,
    source_lock_path: Path | None = None,
) -> ReviewManifestCheckResult:
    """Validate the exact five-file approved boundary with 0/1/2 semantics."""

    return _check_review_manifest(
        manifest_path,
        expected_names=_APPROVED_REVIEW_ARTIFACT_NAMES,
        source_lock=source_lock,
        source_lock_path=source_lock_path,
    )
