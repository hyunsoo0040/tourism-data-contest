"""Closed raw-profile, source, assessment and mood pair for staged promotion."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Self

from pydantic import model_validator

from itda.contracts.base import Sha256, StrictContract, require_utc
from itda.contracts.destination_mood import DestinationMoodBundle
from itda.contracts.grounded_source import GroundedSourceProfile, GroundedSourceRelease
from itda.contracts.mvp_daily_refresh import MvpScoredReleaseV2, MvpScoredReleaseV3
from itda.contracts.mvp_scored_release import MvpScoredRelease
from itda.contracts.source_assessment import AssessmentBundle, AssessmentReleaseManifest
from itda.domain.canonical import canonical_sha256


class GroundedReleaseCandidate(StrictContract):
    schema_version: Literal["grounded-release-candidate.v1"] = "grounded-release-candidate.v1"
    raw_release: GroundedSourceRelease | MvpScoredRelease | MvpScoredReleaseV2 | MvpScoredReleaseV3
    manifest: AssessmentReleaseManifest
    assessments: tuple[AssessmentBundle, ...]
    moods: tuple[DestinationMoodBundle, ...]
    source_snapshots: tuple[dict[str, Any], ...]
    analysis_run: dict[str, Any]
    created_at: datetime
    candidate_sha256: Sha256

    @model_validator(mode="after")
    def validate_pair(self) -> Self:
        from itda.pipeline.destination_evidence import DestinationEvidenceSnapshot

        require_utc(self.created_at, field_name="created_at")
        profiles = {p.place_id: p for p in self.raw_release.profiles}
        ids = tuple(profiles)
        if self.manifest.raw_release_sha256 != self.raw_release.release_sha256:
            raise ValueError("assessment manifest belongs to another raw release")
        if (
            tuple(m.place_id for m in self.manifest.members) != ids
            or tuple(a.place_id for a in self.assessments) != ids
            or tuple(m.place_id for m in self.moods) != ids
        ):
            raise ValueError("grounded candidate must cover exact complete raw membership")
        source_hashes = tuple(sorted(canonical_sha256(s) for s in self.source_snapshots))
        if source_hashes != self.manifest.source_snapshot_sha256:
            raise ValueError("static source payloads differ from manifest hashes")
        snapshots = [DestinationEvidenceSnapshot.model_validate(s) for s in self.source_snapshots]
        if len({s.place.place_id for s in snapshots}) != len(ids) or {
            s.place.place_id for s in snapshots
        } != set(ids):
            raise ValueError("source snapshots must cover exact unique place membership")
        sources = {s.place.place_id: s for s in snapshots}
        members = {m.place_id: m for m in self.manifest.members}
        for assessment, mood in zip(self.assessments, self.moods, strict=True):
            pid = assessment.place_id
            source = sources[pid]
            profile = profiles[pid]
            if isinstance(profile, GroundedSourceProfile) and (
                profile.catalog_row_sha256 != source.catalog_row_sha256
                or profile.place_name_ko != source.place.name_ko
            ):
                raise ValueError("source-only profile and collected place identity differ")
            if (
                assessment.raw_profile_sha256 != profiles[pid].profile_sha256
                or mood.raw_profile_sha256 != profiles[pid].profile_sha256
                or assessment.source_release_sha256 != self.manifest.source_release_sha256
                or mood.source_release_sha256 != self.manifest.source_release_sha256
                or members[pid].raw_profile_sha256 != profiles[pid].profile_sha256
                or members[pid].assessment_bundle_sha256 != assessment.bundle_sha256
            ):
                raise ValueError("grounded place lineage differs from complete pair")
            evidence = {e.evidence_id: e for e in source.evidence}
            for observation in (*assessment.dimensions.values(), *assessment.facts.values()):
                for actual in observation.evidence:
                    original = evidence.get(actual.evidence_id)
                    if (
                        original is None
                        or actual.model_dump(exclude={"quote"})
                        != original.model_dump(exclude={"quote"})
                        or actual.quote not in original.excerpt
                    ):
                        raise ValueError(
                            "assessment cites evidence outside its static source snapshot"
                        )
            for image in mood.images:
                if image.evidence.receipt not in source.receipts:
                    raise ValueError("mood image receipt outside static source snapshot")
        batch = self.analysis_run
        expected_members = [
            {
                "place_id": a.place_id,
                "raw_profile_sha256": a.raw_profile_sha256,
                "assessment_bundle_sha256": a.bundle_sha256,
                "mood_bundle_sha256": m.bundle_sha256,
            }
            for a, m in zip(self.assessments, self.moods, strict=True)
        ]
        if (
            batch.get("schema_version") != "grounded-destination-batch.v1"
            or batch.get("scope") != "PUBLIC_COMPLETE"
            or batch.get("model") != "glm-5.3-flash"
            or batch.get("raw_release_sha256") != self.raw_release.release_sha256
            or batch.get("source_release_sha256") != self.manifest.source_release_sha256
            or batch.get("manifest_sha256") != self.manifest.manifest_sha256
            or batch.get("run_sha256")
            != canonical_sha256({k: v for k, v in batch.items() if k != "run_sha256"})
        ):
            raise ValueError("grounded candidate needs a complete validated production batch")
        actual_members = [
            {k: m.get(k) for k in expected_members[0]}
            for m in batch.get("members", [])
            if isinstance(m, dict)
        ]
        if actual_members != expected_members:
            raise ValueError("batch mood/assessment member hashes differ")
        if self.candidate_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"candidate_sha256"})
        ):
            raise ValueError("grounded candidate pair digest differs")
        return self
