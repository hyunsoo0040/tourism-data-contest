"""Server-authoritative PROF-08 eligibility graph for profile releases.

The resolver consumes only bounded, canonical, digest-only server artifacts.
It deliberately accepts no client readiness flags and emits one generic error
for every invalid graph so protected cohort material cannot cross the boundary.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Any, Literal, Self, cast
from uuid import UUID

from pydantic import Field, StrictBool, model_validator

from itda.cli.freeze_labels import LabelFreezeReceipt
from itda.contracts.base import Sha256, StableId, StrictContract
from itda.contracts.catalog_optional_media import ImageMediumState
from itda.contracts.image_observation import ImageObservationV2
from itda.contracts.phase3_lane_baseline import Phase3LaneBaselineMember
from itda.contracts.phase4_benchmark import (
    ATTRIBUTE_IDS,
    BenchmarkDecisionReport,
    BenchmarkReportState,
    HumanVisibleEvidenceReviewManifest,
    ProvisionalBenchmarkReport,
    ZeroImageFallbackProof,
)
from itda.contracts.place_profile import PlaceProfile, SubattributeId
from itda.contracts.profile_fusion import CANONICAL_FUSION_POLICY, FusionPolicyConfig
from itda.contracts.profile_release import (
    ProfileReleaseCandidate,
    ProfileReleaseCohortMember,
    ProfileReleaseState,
)
from itda.contracts.profile_release_v2 import (
    ProfileReleaseCandidateV2,
    ProfileReleaseCohortMemberV2,
    SuccessorReleaseLineage,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.domain.profile_fusion import build_fused_profile

_MAX_MANIFEST_BYTES = 2_000_000
_RELEASE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_PRINCIPAL_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_ERROR_MESSAGE = "profile release authority bundle is invalid"
_AUTHORITY_FILENAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json$"


class ProfileReleaseBuildAuthorityResolution(StrictContract):
    """Reference to one DB-owned fixed-root authority registration."""

    schema_version: Literal["itda.profile-release-build-authority-resolution.v1"] = (
        "itda.profile-release-build-authority-resolution.v1"
    )
    candidate: ProfileReleaseCandidate | ProfileReleaseCandidateV2
    candidate_sha256: Sha256
    authority_root_sha256: Sha256
    authority_registry_id: UUID
    builder_database_principal: StableId
    expected_predecessor_sha256: Sha256 | None
    expected_predecessor_lifecycle_receipt_sha256: Sha256 | None
    resolution_sha256: Sha256

    @model_validator(mode="after")
    def bind_resolution(self) -> Self:
        expected_predecessor = (
            self.candidate.lineage.predecessor_release_sha256
            if isinstance(self.candidate, ProfileReleaseCandidateV2)
            else None
        )
        expected_predecessor_receipt = (
            self.candidate.lineage.predecessor_lifecycle_receipt_sha256
            if isinstance(self.candidate, ProfileReleaseCandidateV2)
            else None
        )
        if (
            self.candidate_sha256 != self.candidate.release_sha256
            or self.expected_predecessor_sha256 != expected_predecessor
            or self.expected_predecessor_lifecycle_receipt_sha256 != expected_predecessor_receipt
        ):
            raise ValueError("profile release authority predecessor binding is invalid")
        expected = canonical_sha256(
            self.model_dump(
                exclude={"resolution_sha256"},
                mode="json",
            )
        )
        if not hmac.compare_digest(self.resolution_sha256, expected):
            raise ValueError("profile release authority resolution digest is stale")
        return self


def _authority_request_root_sha256(
    request: ProfileReleaseAuthorityRequest | ProfileReleaseAuthorityRequestV2,
) -> str:
    return canonical_sha256(
        {
            "schema_version": "itda.profile-release-fixed-root-request.v1",
            "request": request.model_dump(mode="json"),
        }
    )


def _fixed_root_build_resolution(
    *,
    candidate: ProfileReleaseCandidate | ProfileReleaseCandidateV2,
    authority_root_sha256: str,
    authority_registry_id: UUID,
    builder_database_principal: str,
    expected_predecessor_sha256: str | None,
) -> ProfileReleaseBuildAuthorityResolution:
    payload = {
        "schema_version": "itda.profile-release-build-authority-resolution.v1",
        "candidate": candidate.model_dump(mode="json"),
        "candidate_sha256": candidate.release_sha256,
        "authority_root_sha256": authority_root_sha256,
        "authority_registry_id": str(authority_registry_id),
        "builder_database_principal": builder_database_principal,
        "expected_predecessor_sha256": expected_predecessor_sha256,
        "expected_predecessor_lifecycle_receipt_sha256": (
            candidate.lineage.predecessor_lifecycle_receipt_sha256
            if isinstance(candidate, ProfileReleaseCandidateV2)
            else None
        ),
    }
    resolution_sha256 = canonical_sha256(payload)
    return ProfileReleaseBuildAuthorityResolution(
        candidate=candidate,
        candidate_sha256=cast(str, candidate.release_sha256),
        authority_root_sha256=authority_root_sha256,
        authority_registry_id=authority_registry_id,
        builder_database_principal=builder_database_principal,
        expected_predecessor_sha256=expected_predecessor_sha256,
        expected_predecessor_lifecycle_receipt_sha256=cast(
            str | None,
            payload["expected_predecessor_lifecycle_receipt_sha256"],
        ),
        resolution_sha256=resolution_sha256,
    )


def parse_profile_release_authority_registry_id(raw: str | None) -> UUID:
    """Parse the DB-admin-provisioned fixed-root authority identifier."""

    if raw is None:
        raise RuntimeError("profile release authority registry id is not configured")
    try:
        return UUID(raw)
    except ValueError:
        raise RuntimeError("profile release authority registry id is invalid") from None


class ProfileReleaseAuthorityError(ValueError):
    """Closed failure for every missing, stale, substituted, or mixed bundle."""


class ProfileReleaseAuthorityPaths(StrictContract):
    """Fixed server-held paths; none of these values belongs in a response."""

    label_freeze: Path
    candidate_manifest: Path
    reviewed_manifest: Path
    rights_manifest: Path
    source_manifest: Path


class ProfileReleaseAuthorityRequest(StrictContract):
    """Digest-pinned build intent with no caller-controlled readiness state."""

    release_id: Annotated[str, Field(strict=True, pattern=_RELEASE_ID_PATTERN)]
    builder_principal: Annotated[str, Field(strict=True, pattern=_PRINCIPAL_PATTERN)]
    canonical_lineage_sha256: Sha256
    dev_lineage_sha256: Sha256
    profile_schema_sha256: Sha256
    label_freeze_sha256: Sha256
    candidate_manifest_sha256: Sha256
    reviewed_manifest_sha256: Sha256
    rights_manifest_sha256: Sha256
    source_manifest_sha256: Sha256


class ProfileReleaseAuthorityPathsV2(StrictContract):
    """Root-confined server filenames for the additive successor resolver."""

    root: Path
    predecessor: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    rights: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    lane_baseline: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    selection: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    prediction: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    provisional: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    final: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    review_or_fallback: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    fusion_config: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    profiles: Annotated[str, Field(strict=True, min_length=1, max_length=160)]


class ProfileReleaseAuthorityRequestV2(StrictContract):
    """Digest-only v2 build intent; it carries no approval or readiness flags."""

    release_id: Annotated[str, Field(strict=True, pattern=_RELEASE_ID_PATTERN)]
    builder_principal: Annotated[str, Field(strict=True, pattern=_PRINCIPAL_PATTERN)]
    active_predecessor_sha256: Sha256
    active_predecessor_lifecycle_receipt_sha256: Sha256
    active_predecessor_authority_sha256: Sha256
    rights_manifest_sha256: Sha256
    lane_baseline_manifest_sha256: Sha256
    selection_authority_sha256: Sha256
    prediction_authority_sha256: Sha256
    provisional_authority_sha256: Sha256
    final_authority_sha256: Sha256
    review_or_fallback_authority_sha256: Sha256
    fusion_policy_sha256: Sha256
    profiles_manifest_sha256: Sha256


class _SelfAuthenticatingManifest(StrictContract):
    manifest_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def bind_manifest_digest(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"manifest_sha256"}, mode="json"))
        if self.manifest_sha256 is None:
            object.__setattr__(self, "manifest_sha256", expected)
        elif not hmac.compare_digest(self.manifest_sha256, expected):
            raise ValueError("authority manifest digest is stale")
        return self


class _SourceAuthorityMember(StrictContract):
    place_ref: Annotated[str, Field(strict=True, min_length=1, max_length=200)]
    source_sha256: Sha256
    description_lane: Literal["READY", "MISSING"]
    odii_lane: Literal["READY", "MISSING"]
    source_eligible: StrictBool


class _SourceAuthorityManifest(_SelfAuthenticatingManifest):
    schema_version: Literal["itda.profile-release-source-authority.v1"]
    canonical_lineage_sha256: Sha256
    dev_lineage_sha256: Sha256
    label_source_root_sha256: Sha256
    members: Annotated[tuple[_SourceAuthorityMember, ...], Field(min_length=24, max_length=24)]


class _RightsAuthorityMember(StrictContract):
    place_ref: Annotated[str, Field(strict=True, min_length=1, max_length=200)]
    source_sha256: Sha256
    rights_sha256: Sha256
    rights_eligible: StrictBool


class _RightsAuthorityManifest(_SelfAuthenticatingManifest):
    schema_version: Literal["itda.profile-release-rights-authority.v1"]
    canonical_lineage_sha256: Sha256
    dev_lineage_sha256: Sha256
    source_manifest_sha256: Sha256
    members: Annotated[tuple[_RightsAuthorityMember, ...], Field(min_length=24, max_length=24)]


class _CandidateAuthorityMember(StrictContract):
    place_ref: Annotated[str, Field(strict=True, min_length=1, max_length=200)]
    source_sha256: Sha256
    label_export_sha256: Sha256
    profile_sha256: Sha256
    description_lane: Literal["READY", "MISSING"]
    odii_lane: Literal["READY", "MISSING"]
    complete: StrictBool
    candidate_manifest_sha256: Sha256

    @model_validator(mode="after")
    def bind_member_digest(self) -> Self:
        expected = canonical_sha256(
            self.model_dump(exclude={"candidate_manifest_sha256"}, mode="json")
        )
        if not hmac.compare_digest(self.candidate_manifest_sha256, expected):
            raise ValueError("candidate member digest is stale")
        return self


class _CandidateAuthorityManifest(_SelfAuthenticatingManifest):
    schema_version: Literal["itda.profile-release-candidate-authority.v1"]
    canonical_lineage_sha256: Sha256
    dev_lineage_sha256: Sha256
    profile_schema_sha256: Sha256
    label_freeze_sha256: Sha256
    adjudicated_label_export_sha256: Sha256
    source_manifest_sha256: Sha256
    accepted_revision_set_sha256: Sha256
    code_sha256: Sha256
    config_sha256: Sha256
    members: Annotated[tuple[_CandidateAuthorityMember, ...], Field(min_length=24, max_length=24)]

    @model_validator(mode="after")
    def bind_member_label_exports(self) -> Self:
        if any(
            not hmac.compare_digest(
                member.label_export_sha256,
                self.adjudicated_label_export_sha256,
            )
            for member in self.members
        ):
            raise ValueError("candidate member label export is not frozen")
        return self


class _ReviewedAuthorityMember(StrictContract):
    place_ref: Annotated[str, Field(strict=True, min_length=1, max_length=200)]
    candidate_manifest_sha256: Sha256
    accepted_review_set_sha256: Sha256
    description_lane: Literal["READY", "MISSING"]
    odii_lane: Literal["READY", "MISSING"]
    evidence_eligible: StrictBool
    reviewed_evidence_manifest_sha256: Sha256


class _ReviewedAuthorityManifest(_SelfAuthenticatingManifest):
    schema_version: Literal["itda.profile-release-reviewed-authority.v1"]
    canonical_lineage_sha256: Sha256
    dev_lineage_sha256: Sha256
    profile_schema_sha256: Sha256
    candidate_manifest_sha256: Sha256
    members: Annotated[tuple[_ReviewedAuthorityMember, ...], Field(min_length=24, max_length=24)]


class _V2RightsMember(StrictContract):
    place_ref: Annotated[str, Field(strict=True, min_length=1, max_length=200)]
    predecessor_profile_sha256: Sha256
    predecessor_member_sha256: Sha256
    source_sha256: Sha256
    rights_sha256: Sha256
    reviewed_evidence_manifest_sha256: Sha256


class _V2ActivePredecessorManifest(_SelfAuthenticatingManifest):
    schema_version: Literal["itda.profile-release-v2-active-predecessor-authority.v1"]
    active_release_sha256: Sha256
    lifecycle_state: Literal[ProfileReleaseState.ACTIVE]
    lifecycle_receipt_sha256: Sha256
    candidate: ProfileReleaseCandidate
    profiles: Annotated[tuple[PlaceProfile, ...], Field(min_length=24, max_length=24)]

    @model_validator(mode="after")
    def bind_active_candidate(self) -> Self:
        if not _same_digest(self.active_release_sha256, self.candidate.release_sha256):
            raise ValueError("active predecessor candidate differs from pointer")
        if len({profile.place_id for profile in self.profiles}) != 24:
            raise ValueError("active predecessor profiles are incomplete")
        return self


class _V2RightsManifest(_SelfAuthenticatingManifest):
    schema_version: Literal["itda.profile-release-v2-rights-authority.v1"]
    predecessor_release_sha256: Sha256
    canonical_lineage_sha256: Sha256
    dev_lineage_sha256: Sha256
    source_manifest_sha256: Sha256
    reviewed_manifest_sha256: Sha256
    members: Annotated[tuple[_V2RightsMember, ...], Field(min_length=24, max_length=24)]


class _V2LaneMember(StrictContract):
    place_ref: Annotated[str, Field(strict=True, min_length=1, max_length=200)]
    predecessor_profile_sha256: Sha256
    predecessor_member_sha256: Sha256
    baseline_member_sha256: Sha256
    mismatch_traits_sha256: Sha256
    baseline: Phase3LaneBaselineMember


class _V2LaneManifest(_SelfAuthenticatingManifest):
    schema_version: Literal["itda.profile-release-v2-lane-baseline-authority.v1"]
    predecessor_release_sha256: Sha256
    canonical_lineage_sha256: Sha256
    dev_lineage_sha256: Sha256
    profile_schema_sha256: Sha256
    baseline_sha256: Sha256
    members: Annotated[tuple[_V2LaneMember, ...], Field(min_length=24, max_length=24)]


class _V2SelectionMember(StrictContract):
    place_ref: Annotated[str, Field(strict=True, min_length=1, max_length=200)]
    media_state: ImageMediumState
    selection_member_sha256: Sha256


class _V2SelectionManifest(_SelfAuthenticatingManifest):
    schema_version: Literal["itda.profile-release-v2-selection-authority.v1"]
    selection_manifest_sha256: Sha256
    selection_policy_sha256: Sha256
    members: Annotated[tuple[_V2SelectionMember, ...], Field(min_length=24, max_length=24)]


class _V2PredictionMember(StrictContract):
    place_ref: Annotated[str, Field(strict=True, min_length=1, max_length=200)]
    media_state: ImageMediumState
    prediction_observation_sha256: Sha256
    observation: ImageObservationV2


class _V2PredictionManifest(_SelfAuthenticatingManifest):
    schema_version: Literal["itda.profile-release-v2-prediction-authority.v1"]
    selection_manifest_sha256: Sha256
    prediction_batch_sha256: Sha256
    prediction_freeze_receipt_sha256: Sha256
    members: Annotated[tuple[_V2PredictionMember, ...], Field(min_length=24, max_length=24)]


class _V2ProvisionalManifest(_SelfAuthenticatingManifest):
    schema_version: Literal["itda.profile-release-v2-provisional-authority.v1"]
    place_refs: Annotated[tuple[str, ...], Field(min_length=24, max_length=24)]
    report: ProvisionalBenchmarkReport


class _V2FinalManifest(_SelfAuthenticatingManifest):
    schema_version: Literal["itda.profile-release-v2-final-authority.v1"]
    place_refs: Annotated[tuple[str, ...], Field(min_length=24, max_length=24)]
    report: BenchmarkDecisionReport


class _V2ReviewAuthority(_SelfAuthenticatingManifest):
    schema_version: Literal["itda.profile-release-v2-review-authority.v1"]
    review: HumanVisibleEvidenceReviewManifest | None
    fallback: ZeroImageFallbackProof | None

    @model_validator(mode="after")
    def require_exactly_one_review_authority(self) -> Self:
        if (self.review is None) == (self.fallback is None):
            raise ValueError("successor authority requires exactly one review or fallback")
        return self


class _V2ProfilesManifest(_SelfAuthenticatingManifest):
    schema_version: Literal["itda.profile-release-v2-profile-authority.v1"]
    predecessor_release_sha256: Sha256
    final_report_sha256: Sha256
    fusion_policy_sha256: Sha256
    profile_schema_sha256: Sha256
    code_sha256: Sha256
    config_sha256: Sha256
    members: Annotated[
        tuple[ProfileReleaseCohortMemberV2, ...], Field(min_length=24, max_length=24)
    ]


def _read_bounded_regular_file(path: Path) -> bytes:
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    nofollow_flag = getattr(os, "O_NOFOLLOW", 0)
    if not directory_flag or not nofollow_flag:
        raise OSError("secure file flags unavailable")
    if os.open not in os.supports_dir_fd or os.stat not in os.supports_dir_fd:
        raise OSError("descriptor-relative reads unavailable")

    directory_descriptor = os.open(path.parent, os.O_RDONLY | directory_flag | nofollow_flag)
    try:
        directory_state = os.fstat(directory_descriptor)
        if not stat.S_ISDIR(directory_state.st_mode):
            raise OSError("authority parent is invalid")
        before = os.stat(path.name, dir_fd=directory_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= _MAX_MANIFEST_BYTES
        ):
            raise OSError("authority file is invalid")
        descriptor = os.open(
            path.name,
            os.O_RDONLY | nofollow_flag,
            dir_fd=directory_descriptor,
        )
        try:
            opened = os.fstat(descriptor)
            identity = (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_nlink,
                before.st_size,
                before.st_mtime_ns,
            )
            if identity != (
                opened.st_dev,
                opened.st_ino,
                opened.st_mode,
                opened.st_nlink,
                opened.st_size,
                opened.st_mtime_ns,
            ):
                raise OSError("authority file changed before open")
            chunks: list[bytes] = []
            remaining = opened.st_size
            while remaining:
                chunk = os.read(descriptor, min(remaining, 65_536))
                if not chunk:
                    raise OSError("authority file ended before pinned size")
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(descriptor)
            if identity != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
            ):
                raise OSError("authority file changed during read")
            return raw
        finally:
            os.close(descriptor)
    finally:
        os.close(directory_descriptor)


def _load_canonical_model(path: Path, model: type[StrictContract]) -> StrictContract:
    raw = _read_bounded_regular_file(path)
    try:
        parsed = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("authority file is not canonical JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError("authority file root is invalid")
    validated = model.model_validate(parsed)
    if raw != canonical_json_bytes(validated.model_dump(mode="json")):
        raise ValueError("authority file bytes are not canonical")
    return validated


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    parsed: dict[str, object] = {}
    for key, value in pairs:
        if key in parsed:
            raise ValueError("authority JSON contains duplicate keys")
        parsed[key] = value
    return parsed


def _load_canonical_model_v2(
    root: Path,
    filename: str,
    model: type[StrictContract],
) -> StrictContract:
    if Path(filename).name != filename:
        raise ValueError("authority filename escapes its root")
    raw = _read_bounded_regular_file(root / filename)
    try:
        parsed = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("authority file is not canonical JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError("authority file root is invalid")
    validated = model.model_validate(parsed)
    if raw != canonical_json_bytes(validated.model_dump(mode="json")):
        raise ValueError("authority file bytes are not canonical")
    return validated


def _index_members(members: tuple[Any, ...]) -> dict[str, Any]:
    indexed = {member.place_ref: member for member in members}
    if len(indexed) != 24:
        raise ValueError("authority cohort is incomplete")
    return indexed


def _index_predecessor_profiles(
    profiles: tuple[PlaceProfile, ...],
) -> dict[str, PlaceProfile]:
    indexed = {profile.place_id: profile for profile in profiles}
    if len(indexed) != 24:
        raise ValueError("predecessor profile cohort is incomplete")
    return indexed


def _same_digest(left: str | None, right: str | None) -> bool:
    return isinstance(left, str) and isinstance(right, str) and hmac.compare_digest(left, right)


def _resolve_candidate(
    *,
    request: ProfileReleaseAuthorityRequest,
    freeze: LabelFreezeReceipt,
    source: _SourceAuthorityManifest,
    rights: _RightsAuthorityManifest,
    candidate: _CandidateAuthorityManifest,
    reviewed: _ReviewedAuthorityManifest,
) -> ProfileReleaseCandidate:
    expected_digests = (
        (request.label_freeze_sha256, freeze.receipt_sha256),
        (request.source_manifest_sha256, source.manifest_sha256),
        (request.rights_manifest_sha256, rights.manifest_sha256),
        (request.candidate_manifest_sha256, candidate.manifest_sha256),
        (request.reviewed_manifest_sha256, reviewed.manifest_sha256),
    )
    if any(not _same_digest(actual, expected) for actual, expected in expected_digests):
        raise ValueError("requested authority digest is stale")

    lineages = (
        source.canonical_lineage_sha256,
        rights.canonical_lineage_sha256,
        candidate.canonical_lineage_sha256,
        reviewed.canonical_lineage_sha256,
    )
    dev_lineages = (
        freeze.dev_lineage_sha256,
        source.dev_lineage_sha256,
        rights.dev_lineage_sha256,
        candidate.dev_lineage_sha256,
        reviewed.dev_lineage_sha256,
    )
    schemas = (candidate.profile_schema_sha256, reviewed.profile_schema_sha256)
    if (
        any(not hmac.compare_digest(value, request.canonical_lineage_sha256) for value in lineages)
        or any(not hmac.compare_digest(value, request.dev_lineage_sha256) for value in dev_lineages)
        or any(not hmac.compare_digest(value, request.profile_schema_sha256) for value in schemas)
    ):
        raise ValueError("authority lineage is mixed")
    if not (
        hmac.compare_digest(source.label_source_root_sha256, freeze.source_root_sha256)
        and _same_digest(rights.source_manifest_sha256, source.manifest_sha256)
        and _same_digest(candidate.source_manifest_sha256, source.manifest_sha256)
        and _same_digest(candidate.label_freeze_sha256, freeze.receipt_sha256)
        and hmac.compare_digest(
            candidate.adjudicated_label_export_sha256,
            freeze.adjudicated_label_export_sha256,
        )
        and hmac.compare_digest(
            candidate.accepted_revision_set_sha256,
            freeze.accepted_revision_set_sha256,
        )
        and _same_digest(reviewed.candidate_manifest_sha256, candidate.manifest_sha256)
    ):
        raise ValueError("authority parent link is stale")

    source_by_place = _index_members(source.members)
    rights_by_place = _index_members(rights.members)
    candidate_by_place = _index_members(candidate.members)
    reviewed_by_place = _index_members(reviewed.members)
    place_refs = set(source_by_place)
    if not (
        place_refs == set(rights_by_place)
        and place_refs == set(candidate_by_place)
        and place_refs == set(reviewed_by_place)
    ):
        raise ValueError("authority cohort bindings differ")

    cohort: list[ProfileReleaseCohortMember] = []
    for candidate_member in candidate.members:
        place_ref = candidate_member.place_ref
        source_member = source_by_place[place_ref]
        rights_member = rights_by_place[place_ref]
        reviewed_member = reviewed_by_place[place_ref]
        lanes = (
            source_member.description_lane,
            source_member.odii_lane,
            candidate_member.description_lane,
            candidate_member.odii_lane,
            reviewed_member.description_lane,
            reviewed_member.odii_lane,
        )
        if not (
            source_member.source_eligible
            and rights_member.rights_eligible
            and candidate_member.complete
            and reviewed_member.evidence_eligible
        ):
            raise ValueError("authority member is not eligible")
        if not (
            hmac.compare_digest(source_member.source_sha256, rights_member.source_sha256)
            and hmac.compare_digest(source_member.source_sha256, candidate_member.source_sha256)
            and hmac.compare_digest(
                candidate_member.candidate_manifest_sha256,
                reviewed_member.candidate_manifest_sha256,
            )
            and lanes[0] == lanes[2] == lanes[4]
            and lanes[1] == lanes[3] == lanes[5]
        ):
            raise ValueError("authority member roots differ")
        cohort.append(
            ProfileReleaseCohortMember(
                place_ref=place_ref,
                label_ready=True,
                rights_ready=True,
                evidence_ready=True,
                description_lane=candidate_member.description_lane,
                odii_lane=candidate_member.odii_lane,
                profile_sha256=candidate_member.profile_sha256,
                label_export_sha256=candidate_member.label_export_sha256,
                candidate_manifest_sha256=(candidate_member.candidate_manifest_sha256),
                reviewed_evidence_manifest_sha256=(
                    reviewed_member.reviewed_evidence_manifest_sha256
                ),
                accepted_review_set_sha256=(reviewed_member.accepted_review_set_sha256),
                rights_sha256=rights_member.rights_sha256,
                source_sha256=source_member.source_sha256,
            )
        )

    return ProfileReleaseCandidate(
        release_id=request.release_id,
        builder_principal=request.builder_principal,
        canonical_lineage_sha256=request.canonical_lineage_sha256,
        dev_lineage_sha256=request.dev_lineage_sha256,
        profile_schema_sha256=request.profile_schema_sha256,
        label_freeze_sha256=request.label_freeze_sha256,
        candidate_run_sha256=request.candidate_manifest_sha256,
        reviewed_manifest_sha256=request.reviewed_manifest_sha256,
        rights_manifest_sha256=request.rights_manifest_sha256,
        source_manifest_sha256=request.source_manifest_sha256,
        code_sha256=candidate.code_sha256,
        config_sha256=candidate.config_sha256,
        cohort=tuple(cohort),
    )


def resolve_authoritative_profile_release_candidate(
    *,
    request: ProfileReleaseAuthorityRequest | Mapping[str, object],
    paths: ProfileReleaseAuthorityPaths,
) -> ProfileReleaseCandidate:
    """Resolve one immutable candidate from five verified server-held artifacts."""

    try:
        validated_request = ProfileReleaseAuthorityRequest.model_validate(request)
        freeze = _load_canonical_model(paths.label_freeze, LabelFreezeReceipt)
        candidate = _load_canonical_model(paths.candidate_manifest, _CandidateAuthorityManifest)
        reviewed = _load_canonical_model(paths.reviewed_manifest, _ReviewedAuthorityManifest)
        rights = _load_canonical_model(paths.rights_manifest, _RightsAuthorityManifest)
        source = _load_canonical_model(paths.source_manifest, _SourceAuthorityManifest)
        if not isinstance(freeze, LabelFreezeReceipt):
            raise TypeError("label freeze contract mismatch")
        if not isinstance(candidate, _CandidateAuthorityManifest):
            raise TypeError("candidate authority contract mismatch")
        if not isinstance(reviewed, _ReviewedAuthorityManifest):
            raise TypeError("reviewed authority contract mismatch")
        if not isinstance(rights, _RightsAuthorityManifest):
            raise TypeError("rights authority contract mismatch")
        if not isinstance(source, _SourceAuthorityManifest):
            raise TypeError("source authority contract mismatch")
        return _resolve_candidate(
            request=validated_request,
            freeze=freeze,
            source=source,
            rights=rights,
            candidate=candidate,
            reviewed=reviewed,
        )
    except ProfileReleaseAuthorityError:
        raise
    except Exception:
        raise ProfileReleaseAuthorityError(_ERROR_MESSAGE) from None


def resolve_authoritative_profile_release_build_authority(
    *,
    request: ProfileReleaseAuthorityRequest | Mapping[str, object],
    paths: ProfileReleaseAuthorityPaths,
    authority_registry_id: UUID,
    builder_database_principal: str,
) -> ProfileReleaseBuildAuthorityResolution:
    """Resolve and seal one v1 build against fixed roots and one DB role."""

    validated_request = ProfileReleaseAuthorityRequest.model_validate(request)
    candidate = resolve_authoritative_profile_release_candidate(
        request=validated_request,
        paths=paths,
    )
    return _fixed_root_build_resolution(
        candidate=candidate,
        authority_root_sha256=_authority_request_root_sha256(validated_request),
        authority_registry_id=authority_registry_id,
        builder_database_principal=builder_database_principal,
        expected_predecessor_sha256=None,
    )


def _require_requested_digest(actual: str | None, requested: str) -> None:
    if actual is None or not hmac.compare_digest(actual, requested):
        raise ValueError("successor authority digest is stale")


def _resolve_candidate_v2(
    *,
    request: ProfileReleaseAuthorityRequestV2,
    active_predecessor: _V2ActivePredecessorManifest,
    rights: _V2RightsManifest,
    lane_baseline: _V2LaneManifest,
    selection: _V2SelectionManifest,
    prediction: _V2PredictionManifest,
    provisional: _V2ProvisionalManifest,
    final: _V2FinalManifest,
    review_authority: _V2ReviewAuthority,
    fusion_policy: FusionPolicyConfig,
    profiles: _V2ProfilesManifest,
) -> ProfileReleaseCandidateV2:
    predecessor = active_predecessor.candidate
    requested = (
        (
            active_predecessor.manifest_sha256,
            request.active_predecessor_authority_sha256,
        ),
        (rights.manifest_sha256, request.rights_manifest_sha256),
        (lane_baseline.manifest_sha256, request.lane_baseline_manifest_sha256),
        (selection.manifest_sha256, request.selection_authority_sha256),
        (prediction.manifest_sha256, request.prediction_authority_sha256),
        (provisional.manifest_sha256, request.provisional_authority_sha256),
        (final.manifest_sha256, request.final_authority_sha256),
        (
            review_authority.manifest_sha256,
            request.review_or_fallback_authority_sha256,
        ),
        (fusion_policy.policy_sha256, request.fusion_policy_sha256),
        (profiles.manifest_sha256, request.profiles_manifest_sha256),
    )
    for actual, expected in requested:
        _require_requested_digest(actual, expected)

    if (
        active_predecessor.lifecycle_state is not ProfileReleaseState.ACTIVE
        or not hmac.compare_digest(
            active_predecessor.active_release_sha256,
            request.active_predecessor_sha256,
        )
        or not hmac.compare_digest(
            cast(str, predecessor.release_sha256),
            active_predecessor.active_release_sha256,
        )
        or not hmac.compare_digest(
            active_predecessor.lifecycle_receipt_sha256,
            request.active_predecessor_lifecycle_receipt_sha256,
        )
        or not hmac.compare_digest(
            rights.predecessor_release_sha256, request.active_predecessor_sha256
        )
        or not hmac.compare_digest(
            lane_baseline.predecessor_release_sha256,
            request.active_predecessor_sha256,
        )
        or not hmac.compare_digest(
            profiles.predecessor_release_sha256, request.active_predecessor_sha256
        )
    ):
        raise ValueError("successor active predecessor is stale")

    canonical_lineages = (
        predecessor.canonical_lineage_sha256,
        rights.canonical_lineage_sha256,
        lane_baseline.canonical_lineage_sha256,
    )
    dev_lineages = (
        predecessor.dev_lineage_sha256,
        rights.dev_lineage_sha256,
        lane_baseline.dev_lineage_sha256,
    )
    if any(
        not hmac.compare_digest(value, predecessor.canonical_lineage_sha256)
        for value in canonical_lineages
    ) or any(
        not hmac.compare_digest(value, predecessor.dev_lineage_sha256) for value in dev_lineages
    ):
        raise ValueError("successor authority lineage is mixed")
    if not (
        hmac.compare_digest(rights.source_manifest_sha256, predecessor.source_manifest_sha256)
        and hmac.compare_digest(
            rights.reviewed_manifest_sha256, predecessor.reviewed_manifest_sha256
        )
        and hmac.compare_digest(
            lane_baseline.profile_schema_sha256, predecessor.profile_schema_sha256
        )
    ):
        raise ValueError("successor predecessor authority is mixed")

    predecessor_by_place = _index_members(predecessor.cohort)
    predecessor_profiles_by_place = _index_predecessor_profiles(active_predecessor.profiles)
    rights_by_place = _index_members(rights.members)
    lane_by_place = _index_members(lane_baseline.members)
    selection_by_place = _index_members(selection.members)
    prediction_by_place = _index_members(prediction.members)
    profiles_by_place = _index_members(profiles.members)
    place_refs = set(predecessor_by_place)
    if not all(
        set(indexed) == place_refs
        for indexed in (
            rights_by_place,
            lane_by_place,
            selection_by_place,
            prediction_by_place,
            profiles_by_place,
            predecessor_profiles_by_place,
        )
    ):
        raise ValueError("successor authority cohort is mixed")
    if (
        len(set(provisional.place_refs)) != 24
        or set(provisional.place_refs) != place_refs
        or len(set(final.place_refs)) != 24
        or set(final.place_refs) != place_refs
    ):
        raise ValueError("successor report cohort is mixed")

    for place_ref, predecessor_member in predecessor_by_place.items():
        rights_member = rights_by_place[place_ref]
        lane_member = lane_by_place[place_ref]
        selection_member = selection_by_place[place_ref]
        prediction_member = prediction_by_place[place_ref]
        profile_member = profiles_by_place[place_ref]
        predecessor_profile = predecessor_profiles_by_place[place_ref]
        baseline_body = lane_member.baseline
        observation_body = prediction_member.observation
        expected_predecessor_member = canonical_sha256(predecessor_member.model_dump(mode="json"))
        expected_predecessor_profile = canonical_sha256(predecessor_profile.model_dump(mode="json"))
        if not (
            hmac.compare_digest(
                predecessor_member.profile_sha256,
                rights_member.predecessor_profile_sha256,
            )
            and hmac.compare_digest(
                predecessor_member.profile_sha256,
                lane_member.predecessor_profile_sha256,
            )
            and hmac.compare_digest(
                predecessor_member.profile_sha256,
                profile_member.predecessor_profile_sha256,
            )
            and hmac.compare_digest(
                expected_predecessor_member,
                rights_member.predecessor_member_sha256,
            )
            and hmac.compare_digest(
                expected_predecessor_member,
                lane_member.predecessor_member_sha256,
            )
            and hmac.compare_digest(
                expected_predecessor_member,
                profile_member.predecessor_member_sha256,
            )
            and hmac.compare_digest(predecessor_member.source_sha256, rights_member.source_sha256)
            and hmac.compare_digest(predecessor_member.rights_sha256, rights_member.rights_sha256)
            and hmac.compare_digest(
                predecessor_member.reviewed_evidence_manifest_sha256,
                rights_member.reviewed_evidence_manifest_sha256,
            )
            and hmac.compare_digest(
                lane_member.baseline_member_sha256,
                profile_member.fused_profile.baseline_member_sha256,
            )
            and hmac.compare_digest(
                lane_member.mismatch_traits_sha256,
                canonical_sha256(
                    [
                        trait.model_dump(mode="json")
                        for trait in profile_member.fused_profile.mismatch_traits
                    ]
                ),
            )
            and selection_member.media_state is prediction_member.media_state
            and selection_member.media_state is profile_member.media_state
            and hmac.compare_digest(
                selection_member.selection_member_sha256,
                profile_member.image_selection_member_sha256,
            )
            and hmac.compare_digest(
                prediction_member.prediction_observation_sha256,
                profile_member.prediction_observation_sha256,
            )
            and predecessor_profile.place_id == place_ref
            and hmac.compare_digest(
                expected_predecessor_profile,
                predecessor_member.profile_sha256,
            )
            and baseline_body.place_ref == place_ref
            and hmac.compare_digest(
                baseline_body.profile_sha256,
                predecessor_member.profile_sha256,
            )
            and _same_digest(
                baseline_body.member_sha256,
                lane_member.baseline_member_sha256,
            )
            and observation_body.media_state is prediction_member.media_state
            and observation_body.media_state is selection_member.media_state
            and hmac.compare_digest(
                observation_body.representative_manifest_sha256,
                selection.selection_manifest_sha256,
            )
            and hmac.compare_digest(
                observation_body.observation_sha256,
                prediction_member.prediction_observation_sha256,
            )
        ):
            raise ValueError("successor member authority is mixed")
        rebuilt_profile = build_fused_profile(
            baseline_body,
            observation_body,
            predecessor_profile=predecessor_profile,
            policy=CANONICAL_FUSION_POLICY,
        )
        if canonical_json_bytes(rebuilt_profile.model_dump(mode="json")) != canonical_json_bytes(
            profile_member.fused_profile.model_dump(mode="json")
        ):
            raise ValueError("successor fused profile differs from source authority")

    experiment = provisional.report.experiment
    decision = final.report
    if experiment.evaluation_scope != "DEV_24_PROTECTED":
        raise ValueError("successor release requires protected DEV authority")
    if provisional.report.state is not BenchmarkReportState.PROVISIONAL_PENDING_HUMAN_REVIEW:
        raise ValueError("successor provisional report state is invalid")
    if decision.state in {
        BenchmarkReportState.PROVISIONAL_PENDING_HUMAN_REVIEW,
        BenchmarkReportState.PENDING_EXTERNAL_EVIDENCE,
        BenchmarkReportState.REJECT,
    }:
        raise ValueError("successor terminal report is not release eligible")
    if not (
        hmac.compare_digest(
            experiment.selection_manifest_sha256,
            selection.selection_manifest_sha256,
        )
        and hmac.compare_digest(
            experiment.selection_policy_sha256,
            selection.selection_policy_sha256,
        )
        and hmac.compare_digest(
            prediction.selection_manifest_sha256,
            selection.selection_manifest_sha256,
        )
        and hmac.compare_digest(
            experiment.prediction_batch_sha256,
            prediction.prediction_batch_sha256,
        )
        and hmac.compare_digest(experiment.baseline_sha256, lane_baseline.baseline_sha256)
        and hmac.compare_digest(
            decision.provisional_report_sha256,
            provisional.report.provisional_report_sha256,
        )
        and hmac.compare_digest(profiles.final_report_sha256, decision.final_report_sha256)
    ):
        raise ValueError("successor benchmark authority is mixed")
    if (
        fusion_policy.mode != "CANONICAL_RELEASE"
        or not fusion_policy.release_eligible
        or fusion_policy.policy_sha256 != CANONICAL_FUSION_POLICY.policy_sha256
        or experiment.fusion_policy_sha256 != CANONICAL_FUSION_POLICY.policy_sha256
        or decision.locked_fusion_policy_sha256 != CANONICAL_FUSION_POLICY.policy_sha256
        or profiles.fusion_policy_sha256 != CANONICAL_FUSION_POLICY.policy_sha256
    ):
        raise ValueError("successor fusion policy is release ineligible")

    human_review_sha256: str | None = None
    fallback_sha256: str | None = None
    if decision.state in {BenchmarkReportState.ADOPT, BenchmarkReportState.CONDITIONAL_ADOPT}:
        review = review_authority.review
        if review is None or review_authority.fallback is not None:
            raise ValueError("image adoption requires human review")
        if not (
            _same_digest(decision.human_review_manifest_sha256, review.review_manifest_sha256)
            and decision.zero_image_fallback_sha256 is None
            and hmac.compare_digest(
                review.provisional_report_sha256,
                provisional.report.provisional_report_sha256,
            )
            and hmac.compare_digest(
                review.prediction_batch_sha256, prediction.prediction_batch_sha256
            )
            and hmac.compare_digest(
                review.selection_manifest_sha256,
                selection.selection_manifest_sha256,
            )
            and decision.image_contribution_count > 0
        ):
            raise ValueError("human review authority is incomplete")
        human_review_sha256 = review.review_manifest_sha256
        adopted = set(decision.adopted_attributes)
        inherited = set(decision.inherited_baseline_attributes)
        if decision.state is BenchmarkReportState.CONDITIONAL_ADOPT and (
            not adopted
            or not adopted.issubset(set(experiment.predeclared_conditional_attributes))
            or adopted & inherited
            or adopted | inherited != set(ATTRIBUTE_IDS)
        ):
            raise ValueError("conditional adoption scope is invalid")
    else:
        fallback = review_authority.fallback
        if fallback is None or review_authority.review is not None:
            raise ValueError("text-only release requires a zero-image fallback")
        if not (
            decision.human_review_manifest_sha256 is None
            and _same_digest(decision.zero_image_fallback_sha256, fallback.proof_sha256)
            and decision.state is fallback.outcome
            and decision.image_contribution_count == 0
            and not decision.adopted_attributes
        ):
            raise ValueError("zero-image report authority is incomplete")
        fallback_sha256 = fallback.proof_sha256

    policy_sha256 = fusion_policy.policy_sha256
    if policy_sha256 is None:
        raise ValueError("successor fusion policy digest is absent")

    lineage = SuccessorReleaseLineage(
        predecessor_release_sha256=request.active_predecessor_sha256,
        predecessor_lifecycle_receipt_sha256=(request.active_predecessor_lifecycle_receipt_sha256),
        canonical_lineage_sha256=predecessor.canonical_lineage_sha256,
        dev_lineage_sha256=predecessor.dev_lineage_sha256,
        rights_manifest_sha256=request.rights_manifest_sha256,
        source_manifest_sha256=predecessor.source_manifest_sha256,
        reviewed_manifest_sha256=predecessor.reviewed_manifest_sha256,
        lane_baseline_sha256=lane_baseline.baseline_sha256,
        image_selection_manifest_sha256=selection.selection_manifest_sha256,
        prediction_batch_sha256=prediction.prediction_batch_sha256,
        prediction_freeze_receipt_sha256=prediction.prediction_freeze_receipt_sha256,
        provisional_report_sha256=provisional.report.provisional_report_sha256,
        final_report_sha256=decision.final_report_sha256,
        human_review_manifest_sha256=human_review_sha256,
        zero_image_fallback_sha256=fallback_sha256,
        fusion_policy_sha256=policy_sha256,
        profile_schema_sha256=profiles.profile_schema_sha256,
        code_sha256=profiles.code_sha256,
        config_sha256=profiles.config_sha256,
    )
    return ProfileReleaseCandidateV2(
        release_id=request.release_id,
        builder_principal=request.builder_principal,
        adoption_state=decision.state,
        adopted_attributes=tuple(SubattributeId(value) for value in decision.adopted_attributes),
        fusion_policy=fusion_policy,
        lineage=lineage,
        cohort=profiles.members,
    )


def resolve_authoritative_profile_release_candidate_v2(
    *,
    request: ProfileReleaseAuthorityRequestV2 | Mapping[str, object],
    paths: ProfileReleaseAuthorityPathsV2,
) -> ProfileReleaseCandidateV2:
    """Resolve one exact unapproved successor from root-confined manifests."""

    try:
        validated_request = ProfileReleaseAuthorityRequestV2.model_validate(request)
        filenames = (
            paths.predecessor,
            paths.rights,
            paths.lane_baseline,
            paths.selection,
            paths.prediction,
            paths.provisional,
            paths.final,
            paths.review_or_fallback,
            paths.fusion_config,
            paths.profiles,
        )
        if len(set(filenames)) != len(filenames) or any(
            Path(filename).name != filename
            or re.fullmatch(_AUTHORITY_FILENAME_PATTERN, filename) is None
            for filename in filenames
        ):
            raise ValueError("successor authority filenames are invalid")
        active_predecessor = _load_canonical_model_v2(
            paths.root, paths.predecessor, _V2ActivePredecessorManifest
        )
        rights = _load_canonical_model_v2(paths.root, paths.rights, _V2RightsManifest)
        lane_baseline = _load_canonical_model_v2(paths.root, paths.lane_baseline, _V2LaneManifest)
        selection = _load_canonical_model_v2(paths.root, paths.selection, _V2SelectionManifest)
        prediction = _load_canonical_model_v2(paths.root, paths.prediction, _V2PredictionManifest)
        provisional = _load_canonical_model_v2(
            paths.root, paths.provisional, _V2ProvisionalManifest
        )
        final = _load_canonical_model_v2(paths.root, paths.final, _V2FinalManifest)
        review_authority = _load_canonical_model_v2(
            paths.root, paths.review_or_fallback, _V2ReviewAuthority
        )
        fusion_policy = _load_canonical_model_v2(
            paths.root, paths.fusion_config, FusionPolicyConfig
        )
        profiles = _load_canonical_model_v2(paths.root, paths.profiles, _V2ProfilesManifest)
        return _resolve_candidate_v2(
            request=validated_request,
            active_predecessor=cast(_V2ActivePredecessorManifest, active_predecessor),
            rights=cast(_V2RightsManifest, rights),
            lane_baseline=cast(_V2LaneManifest, lane_baseline),
            selection=cast(_V2SelectionManifest, selection),
            prediction=cast(_V2PredictionManifest, prediction),
            provisional=cast(_V2ProvisionalManifest, provisional),
            final=cast(_V2FinalManifest, final),
            review_authority=cast(_V2ReviewAuthority, review_authority),
            fusion_policy=cast(FusionPolicyConfig, fusion_policy),
            profiles=cast(_V2ProfilesManifest, profiles),
        )
    except ProfileReleaseAuthorityError:
        raise
    except Exception:
        raise ProfileReleaseAuthorityError(_ERROR_MESSAGE) from None


def resolve_authoritative_profile_release_build_authority_v2(
    *,
    request: ProfileReleaseAuthorityRequestV2 | Mapping[str, object],
    paths: ProfileReleaseAuthorityPathsV2,
    authority_registry_id: UUID,
    builder_database_principal: str,
) -> ProfileReleaseBuildAuthorityResolution:
    """Resolve and seal one successor build against fixed roots and one DB role."""

    validated_request = ProfileReleaseAuthorityRequestV2.model_validate(request)
    candidate = resolve_authoritative_profile_release_candidate_v2(
        request=validated_request,
        paths=paths,
    )
    return _fixed_root_build_resolution(
        candidate=candidate,
        authority_root_sha256=_authority_request_root_sha256(validated_request),
        authority_registry_id=authority_registry_id,
        builder_database_principal=builder_database_principal,
        expected_predecessor_sha256=candidate.lineage.predecessor_release_sha256,
    )


__all__ = [
    "ProfileReleaseBuildAuthorityResolution",
    "ProfileReleaseAuthorityError",
    "ProfileReleaseAuthorityPaths",
    "ProfileReleaseAuthorityPathsV2",
    "ProfileReleaseAuthorityRequest",
    "ProfileReleaseAuthorityRequestV2",
    "parse_profile_release_authority_registry_id",
    "resolve_authoritative_profile_release_candidate",
    "resolve_authoritative_profile_release_candidate_v2",
    "resolve_authoritative_profile_release_build_authority",
    "resolve_authoritative_profile_release_build_authority_v2",
]
