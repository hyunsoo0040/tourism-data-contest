"""Pinned auxiliary observations for visual matching, facilities and photo display."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Self

from pydantic import Field, model_validator

from itda.authenticity.contracts import Assessment
from itda.contracts.base import Sha256, StableId, StrictContract
from itda.contracts.destination_mood import DestinationMoodBundle
from itda.contracts.grounded_recommendation import RequiredFacility
from itda.contracts.source_assessment import ClaimKind, SourceObservation
from itda.domain.canonical import canonical_sha256


class PublicPhoto(StrictContract):
    original_sha256: Sha256
    url: str
    attribution_ko: str
    license: str


class Auxiliary(StrictContract):
    moods: dict[StableId, DestinationMoodBundle] = Field(default_factory=dict)
    facilities: dict[StableId, dict[RequiredFacility, SourceObservation]] = Field(
        default_factory=dict
    )
    photos: dict[StableId, tuple[PublicPhoto, ...]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def bindings(self) -> Self:
        for pid, mood in self.moods.items():
            if mood.place_id != pid:
                raise ValueError("AUXILIARY_MOOD_PLACE_MISMATCH")
        for pid, facts in self.facilities.items():
            for fact in facts.values():
                if fact.claim != ClaimKind.FACILITY or any(
                    e.place_match is None or e.place_match.place_id != pid for e in fact.evidence
                ):
                    raise ValueError("AUXILIARY_FACILITY_PLACE_MISMATCH")
        for pid, photos in self.photos.items():
            approved = (
                {i.original_sha256 for i in self.moods[pid].images} if pid in self.moods else set()
            )
            if any(p.original_sha256 not in approved or p.license != "KOGL_TYPE_1" for p in photos):
                raise ValueError("AUXILIARY_PHOTO_NOT_LICENSED_AND_SELECTED")
        return self

    @property
    def digest(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))


def from_national(assessments: tuple[Assessment, ...], repository: Path) -> Auxiliary:
    moods = {}
    facilities = {}
    photos = {}
    roots = {
        "initial": repository / "artifacts/national/20260909/analysis",
        "additional": repository
        / "artifacts/national/20260911-additional-1000/analysis-recovery-20260911",
    }
    for a in assessments:
        root = roots.get(a.source.place.cohort)
        if root is None:
            continue
        pid = a.source.place.place_id
        stem = pid.split(":")[-1]
        mood = DestinationMoodBundle.model_validate_json(
            (root / "moods" / (stem + ".json")).read_bytes()
        )
        moods[pid] = mood
        original = json.loads((root / "sources" / (stem + ".json")).read_text())
        assets = {i["original_sha256"]: i for i in original["images"] if i.get("original_sha256")}
        photos[pid] = tuple(
            PublicPhoto(
                original_sha256=i.original_sha256,
                url=assets[i.original_sha256]["url"],
                attribution_ko=i.attribution_ko,
                license="KOGL_TYPE_1",
            )
            for i in mood.images
        )
        old = json.loads((root / "assessments" / (stem + ".json")).read_text())
        facts = {}
        for key, value in old.get("facts", {}).items():
            if key in set(RequiredFacility):
                fact = SourceObservation.model_validate(value)
                if fact.claim == ClaimKind.FACILITY:
                    facts[RequiredFacility(key)] = fact
        facilities[pid] = facts
    return Auxiliary(moods=moods, facilities=facilities, photos=photos)
