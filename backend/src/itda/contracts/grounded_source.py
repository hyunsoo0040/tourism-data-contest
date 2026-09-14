"""Fresh source identities for grounded analysis, without fabricated legacy scores."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Annotated, Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StrictContract, require_utc
from itda.contracts.mvp_public_catalog import (
    PublicPlaceCatalog,
    PublicPlaceId,
    PublicPlaceRelations,
)
from itda.domain.canonical import canonical_sha256

if TYPE_CHECKING:
    from itda.contracts.mvp_daily_refresh import DailyScoredRelease


class GroundedSourceProfile(StrictContract):
    schema_version: Literal["grounded-source-profile.v1"] = "grounded-source-profile.v1"
    place_id: PublicPlaceId
    place_name_ko: Annotated[str, Field(min_length=1, max_length=240)]
    duplicate_group_id: Annotated[str, Field(pattern=r"^duplicate:[0-9a-f]{64}$")]
    catalog_row_sha256: Sha256
    source_evidence_ids: Annotated[tuple[str, ...], Field(min_length=1, max_length=8)]
    recommendation_eligible: Literal[True] = True
    profile_sha256: Sha256

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        if self.source_evidence_ids != tuple(sorted(set(self.source_evidence_ids))):
            raise ValueError("source profile evidence IDs must be unique and sorted")
        if self.profile_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"profile_sha256"})
        ):
            raise ValueError("source profile hash differs")
        return self


class GroundedSourceRelease(StrictContract):
    schema_version: Literal["grounded-source-release.v1"] = "grounded-source-release.v1"
    catalog_sha256: Sha256
    evidence_inventory_sha256: Sha256
    source_relations_sha256: Sha256
    published_count: Annotated[int, Field(strict=True, ge=1, le=1000)]
    profiles: Annotated[tuple[GroundedSourceProfile, ...], Field(min_length=1, max_length=1000)]
    membership_sha256: Sha256
    relation_sha256: Sha256
    relation_pairs: tuple[tuple[PublicPlaceId, PublicPlaceId], ...]
    created_at: datetime
    release_sha256: Sha256

    @model_validator(mode="after")
    def validate_membership(self) -> Self:
        from itda.contracts.recommendation import public_relation_sha256

        require_utc(self.created_at, field_name="created_at")
        ids = tuple(profile.place_id for profile in self.profiles)
        if ids != tuple(sorted(set(ids))) or self.published_count != len(ids):
            raise ValueError("source release membership must be complete and unique")
        if self.membership_sha256 != canonical_sha256(list(ids)):
            raise ValueError("source release membership hash differs")
        if self.relation_pairs != tuple(sorted(set(self.relation_pairs))) or any(
            left >= right or left not in ids or right not in ids
            for left, right in self.relation_pairs
        ):
            raise ValueError("source release relation membership differs")
        if self.relation_sha256 != public_relation_sha256(ids, self.relation_pairs):
            raise ValueError("source release relation hash differs")
        if self.release_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"release_sha256"})
        ):
            raise ValueError("source release hash differs")
        return self


def build_source_release(
    catalog: PublicPlaceCatalog, relations: PublicPlaceRelations, *, created_at: datetime
) -> GroundedSourceRelease:
    from itda.contracts.recommendation import public_relation_sha256

    ids = tuple(place.place_id for place in catalog.places)
    if relations.catalog_sha256 != catalog.catalog_sha256 or relations.catalog_place_ids != ids:
        raise ValueError("source catalog and relation authority differ")
    profiles = []
    for place in catalog.places:
        payload = {
            "schema_version": "grounded-source-profile.v1",
            "place_id": place.place_id,
            "place_name_ko": place.name_ko,
            "duplicate_group_id": place.duplicate_group_id,
            "catalog_row_sha256": place.row_sha256,
            "source_evidence_ids": list(place.evidence_ids),
            "recommendation_eligible": True,
        }
        profiles.append(payload | {"profile_sha256": canonical_sha256(payload)})
    pairs = tuple((row.left_place_id, row.right_place_id) for row in relations.relations)
    payload = {
        "schema_version": "grounded-source-release.v1",
        "catalog_sha256": catalog.catalog_sha256,
        "evidence_inventory_sha256": catalog.evidence_inventory_sha256,
        "source_relations_sha256": relations.relations_sha256,
        "published_count": len(ids),
        "profiles": profiles,
        "membership_sha256": canonical_sha256(list(ids)),
        "relation_sha256": public_relation_sha256(ids, pairs),
        "relation_pairs": [list(pair) for pair in pairs],
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
    }
    return GroundedSourceRelease.model_validate(
        payload | {"release_sha256": canonical_sha256(payload)}
    )


def parse_grounded_input_release(payload: object) -> GroundedSourceRelease | DailyScoredRelease:
    """Read source-only inputs or historical scored releases without converting either."""
    from itda.contracts.mvp_daily_refresh import parse_daily_scored_release

    if isinstance(payload, dict) and payload.get("schema_version") == "grounded-source-release.v1":
        return GroundedSourceRelease.model_validate(payload)
    return parse_daily_scored_release(payload)
