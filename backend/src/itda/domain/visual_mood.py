"""Canonical aggregation of confirmed distinct-image appearance observations."""

from __future__ import annotations

from typing import Literal

from itda.contracts.visual_mood import (
    MOOD_POLICY_SHA256,
    ConfirmedMoodProjection,
    MoodChoice,
    MoodObservation,
    PhotoMoodCandidateSet,
    ProjectedMood,
    VisualMoodDimension,
)
from itda.domain.canonical import canonical_sha256


def build_candidate_set(
    *,
    job_id: str,
    image_index: int,
    image_sha256: str,
    observations: tuple[MoodObservation, ...],
    provider_id: str,
    analysis_kind: Literal["MODEL", "SYNTHETIC"],
    model: Literal["glm-5.3-flash"] | None,
) -> PhotoMoodCandidateSet:
    ordered = sorted(observations, key=lambda row: tuple(VisualMoodDimension).index(row.dimension))
    payload = {
        "schema_version": "photo-mood-candidates.v1",
        "family": "photo-mood-v1",
        "mood_version": "visual-mood-v1",
        "authority_scope": "VISUAL_MOOD_ONLY",
        "job_id": job_id,
        "image_index": image_index,
        "payload_sha256": image_sha256,
        "policy_sha256": MOOD_POLICY_SHA256,
        "provider_id": provider_id,
        "analysis_kind": analysis_kind,
        "model": model,
        "candidates": [
            {
                "candidate_id": canonical_sha256(
                    {
                        "job_id": job_id,
                        "image": image_sha256,
                        "observation": row.model_dump(mode="json"),
                        "provider_id": provider_id,
                        "policy_sha256": MOOD_POLICY_SHA256,
                    }
                ),
                "observation": row.model_dump(mode="json"),
            }
            for row in ordered
        ],
    }
    return PhotoMoodCandidateSet.model_validate(
        payload | {"candidate_set_sha256": canonical_sha256(payload)}
    )


def aggregate_moods(
    batches: tuple[PhotoMoodCandidateSet, ...],
    *,
    selected_candidate_ids: tuple[str, ...] | None = None,
) -> tuple[ProjectedMood, ...]:
    images: dict[str, PhotoMoodCandidateSet] = {}
    for batch in batches:
        batch = PhotoMoodCandidateSet.model_validate_json(batch.model_dump_json())
        previous = images.setdefault(batch.payload_sha256, batch)
        if previous.candidates != batch.candidates:
            raise ValueError("duplicate image has conflicting appearance observations")
    selected = set(selected_candidate_ids) if selected_candidate_ids is not None else None
    known = {candidate.candidate_id for batch in images.values() for candidate in batch.candidates}
    if selected is not None and not selected <= known:
        raise ValueError("unknown appearance candidate selection")
    result = []
    for dimension in VisualMoodDimension:
        rows = [
            candidate
            for batch in images.values()
            for candidate in batch.candidates
            if candidate.observation.dimension == dimension
            and candidate.observation.state == "OBSERVED"
            and (selected is None or candidate.candidate_id in selected)
        ]
        numerator = 0
        for row in rows:
            assert row.observation.level is not None
            numerator += row.observation.level * 25
        result.append(
            ProjectedMood(
                dimension=dimension,
                value=(2 * numerator + len(rows)) // (2 * len(rows)) if rows else None,
                distinct_images=len(rows),
                candidate_ids=tuple(sorted(row.candidate_id for row in rows)),
            )
        )
    return tuple(result)


def mood_draft_sha256(
    *, job_id: str, profile_id: str, batches: tuple[PhotoMoodCandidateSet, ...]
) -> str:
    return canonical_sha256(
        {
            "schema_version": "photo-mood-draft.v1",
            "job_id": job_id,
            "preference_profile_id": profile_id,
            "policy_sha256": MOOD_POLICY_SHA256,
            "candidate_set_sha256": sorted({b.candidate_set_sha256 for b in batches}),
        }
    )


def confirm_moods(
    *,
    job_id: str,
    profile_id: str,
    batches: tuple[PhotoMoodCandidateSet, ...],
    choices: tuple[MoodChoice, ...],
    draft_sha256: str,
) -> ConfirmedMoodProjection:
    if any(batch.job_id != job_id for batch in batches):
        raise ValueError("appearance batch belongs to another job")
    if draft_sha256 != mood_draft_sha256(job_id=job_id, profile_id=profile_id, batches=batches):
        raise ValueError("appearance draft changed")
    available = {
        candidate.candidate_id: candidate for batch in batches for candidate in batch.candidates
    }
    if len({row.candidate_id for row in choices}) != len(choices):
        raise ValueError("duplicate appearance selection")
    for row in choices:
        if row.candidate_id not in available or (
            row.included and available[row.candidate_id].observation.state != "OBSERVED"
        ):
            raise ValueError("unobserved or foreign appearance candidate")
    selected = tuple(row.candidate_id for row in choices if row.included)
    payload = {
        "schema_version": "photo-mood-projection.v1",
        "family": "photo-mood-v1",
        "job_id": job_id,
        "preference_profile_id": profile_id,
        "policy_sha256": MOOD_POLICY_SHA256,
        "draft_sha256": draft_sha256,
        "candidate_set_sha256": sorted({b.candidate_set_sha256 for b in batches}),
        "choices": [
            row.model_dump(mode="json") for row in sorted(choices, key=lambda row: row.candidate_id)
        ],
        "moods": [
            row.model_dump(mode="json")
            for row in aggregate_moods(batches, selected_candidate_ids=selected)
        ],
    }
    return ConfirmedMoodProjection.model_validate(
        payload | {"receipt_id": canonical_sha256(payload)}
    )
