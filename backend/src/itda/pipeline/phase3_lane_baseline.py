"""Exact, read-only projection of authority-produced Phase 3 medium lanes."""

from __future__ import annotations

import hmac
import json
from collections.abc import Mapping

from itda.contracts.phase3_lane_baseline import (
    Phase3LaneAuthorityBundle,
    Phase3LaneBaseline,
    Phase3LaneBaselineMember,
    Phase3LaneBaselineResult,
)
from itda.contracts.place_profile import PlaceProfile
from itda.contracts.profile_release import ProfileReleaseCandidate
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

_ERROR_MESSAGE = "phase 3 lane baseline authority is invalid"
_PROJECTION_RULE = {
    "schema_version": "itda.phase3-lane-projection-rule.v1",
    "profile_body_rule": "CANONICAL_PLACE_PROFILE_BYTES_MUST_MATCH_PREDECESSOR_HASH",
    "lane_rule": "ONLY_PHASE3_PROFILE_CONSTRUCTION_LANE_VALUES",
    "missing_rule": "PRESERVE_MISSING_WITHOUT_IMPUTATION",
    "candidate_similarity_rule": "FORBIDDEN_AS_PROFILE_LANE_VALUES",
}


class Phase3LaneBaselineAuthorityError(ValueError):
    """Generic failure for malformed, stale, partial, or substituted material."""


def _same(left: str | None, right: str | None) -> bool:
    return isinstance(left, str) and isinstance(right, str) and hmac.compare_digest(left, right)


def _canonical_profile(raw: bytes, *, place_ref: str) -> tuple[PlaceProfile, str]:
    if not isinstance(raw, bytes) or not raw:
        raise ValueError("predecessor profile body is missing")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("predecessor profile body is not JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("predecessor profile body root is invalid")
    profile = PlaceProfile.model_validate(payload)
    canonical = canonical_json_bytes(profile.model_dump(mode="json"))
    if raw != canonical or profile.place_id != place_ref:
        raise ValueError("predecessor profile bytes are not canonical")
    return profile, canonical_sha256(profile.model_dump(mode="json"))


def project_phase3_lane_baseline(
    *,
    predecessor_release: ProfileReleaseCandidate | Mapping[str, object],
    active_release_sha256: str,
    profile_bodies: Mapping[str, bytes],
    authority_bundle: Phase3LaneAuthorityBundle | Mapping[str, object] | None,
    trusted_authority_sha256: str | None = None,
) -> Phase3LaneBaselineResult:
    """Project exact preserved lanes, or report that protected evidence is absent.

    The pending branch intentionally returns before profile, text, encoder, or cache
    observation. Phase 4 never recreates discarded Phase 3 medium values.
    """

    if authority_bundle is None:
        return Phase3LaneBaselineResult(
            status="PENDING_PROTECTED_BASELINE",
            reason="PROTECTED_PHASE3_LANE_AUTHORITY_UNAVAILABLE",
            baseline=None,
        )

    try:
        release = ProfileReleaseCandidate.model_validate(predecessor_release)
        authority = Phase3LaneAuthorityBundle.model_validate(authority_bundle)
        if not _same(trusted_authority_sha256, authority.authority_sha256):
            raise ValueError("phase 3 lane authority is not server-trusted")
        release_sha256 = str(release.release_sha256)
        if not _same(active_release_sha256, release_sha256):
            raise ValueError("predecessor release is not active")
        lineage_pairs = (
            (authority.predecessor_release_sha256, release_sha256),
            (authority.canonical_lineage_sha256, release.canonical_lineage_sha256),
            (authority.dev_lineage_sha256, release.dev_lineage_sha256),
            (authority.profile_schema_sha256, release.profile_schema_sha256),
            (authority.source_manifest_sha256, release.source_manifest_sha256),
            (authority.reviewed_manifest_sha256, release.reviewed_manifest_sha256),
        )
        if any(not _same(left, right) for left, right in lineage_pairs):
            raise ValueError("phase 3 lane authority lineage is stale")
        expected_refs = [member.place_ref for member in release.cohort]
        authority_refs = [member.place_ref for member in authority.members]
        if authority_refs != expected_refs or set(profile_bodies) != set(expected_refs):
            raise ValueError("phase 3 lane authority cohort differs")

        projected: list[Phase3LaneBaselineMember] = []
        for release_member, authority_member in zip(release.cohort, authority.members, strict=True):
            profile, profile_sha256 = _canonical_profile(
                profile_bodies[release_member.place_ref],
                place_ref=release_member.place_ref,
            )
            if not (
                _same(profile_sha256, release_member.profile_sha256)
                and _same(profile_sha256, authority_member.profile_sha256)
                and authority_member.description.status == release_member.description_lane
                and authority_member.odii.status == release_member.odii_lane
            ):
                raise ValueError("phase 3 lane authority member differs")
            inherited_traits = tuple(
                (trait.trait_id, trait.value) for trait in profile.mismatch_traits
            )
            authority_traits = tuple(
                (trait.trait_id, trait.value) for trait in authority_member.mismatch_traits
            )
            if inherited_traits != authority_traits:
                raise ValueError("phase 3 mismatch traits differ from predecessor")
            projected.append(
                Phase3LaneBaselineMember.model_validate(authority_member.model_dump(mode="json"))
            )

        baseline = Phase3LaneBaseline(
            predecessor_release_sha256=release_sha256,
            canonical_lineage_sha256=release.canonical_lineage_sha256,
            dev_lineage_sha256=release.dev_lineage_sha256,
            profile_schema_sha256=release.profile_schema_sha256,
            source_manifest_sha256=release.source_manifest_sha256,
            reviewed_manifest_sha256=release.reviewed_manifest_sha256,
            authority_sha256=str(authority.authority_sha256),
            projection_rule_sha256=canonical_sha256(_PROJECTION_RULE),
            members=tuple(projected),
        )
        return Phase3LaneBaselineResult(status="READY", baseline=baseline)
    except Phase3LaneBaselineAuthorityError:
        raise
    except Exception:
        raise Phase3LaneBaselineAuthorityError(_ERROR_MESSAGE) from None


__all__ = [
    "Phase3LaneBaselineAuthorityError",
    "project_phase3_lane_baseline",
]
