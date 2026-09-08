"""Strict contracts for the Phase 1 synthetic evaluation manifest."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import Field, model_validator

from itda.contracts.base import DataSplit, Sha256, StableId, StrictContract, Version, require_utc

CANONICALIZATION_VERSION = "canonical-json-v1"
_SPLIT_ORDER = {DataSplit.DEV: 0, DataSplit.BLIND: 1}


class SplitManifestMember(StrictContract):
    """One deliberately synthetic DEV or BLIND membership row."""

    synthetic_place_id: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=160),
    ]
    split: DataSplit

    @model_validator(mode="after")
    def enforce_synthetic_split_identity(self) -> SplitManifestMember:
        if not self.synthetic_place_id.startswith("synthetic:"):
            raise ValueError("synthetic_place_id must start with synthetic:")
        expected_prefix = f"synthetic:{self.split.value.casefold()}:"
        if self.split not in _SPLIT_ORDER or not self.synthetic_place_id.startswith(
            expected_prefix
        ):
            raise ValueError("synthetic_place_id prefix must match its DEV or BLIND split")
        return self


class SplitManifest(StrictContract):
    """The only manifest shape that Phase 1 is allowed to seal."""

    manifest_version: Version
    canonicalization_version: Version
    members: tuple[SplitManifestMember, ...]

    @model_validator(mode="after")
    def enforce_phase_one_boundary(self) -> SplitManifest:
        if self.canonicalization_version != CANONICALIZATION_VERSION:
            raise ValueError("canonicalization_version must be canonical-json-v1")

        identifiers = [member.synthetic_place_id for member in self.members]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("synthetic_place_id values must be unique")

        dev_count = sum(member.split is DataSplit.DEV for member in self.members)
        blind_count = sum(member.split is DataSplit.BLIND for member in self.members)
        if (dev_count, blind_count) != (24, 12):
            raise ValueError("manifest must contain exactly 24 DEV and 12 BLIND members")
        return self

    def canonical_members(self) -> tuple[SplitManifestMember, ...]:
        """Return members in the one canonical split-and-ID order."""

        return tuple(
            sorted(
                self.members,
                key=lambda member: (
                    _SPLIT_ORDER[member.split],
                    member.synthetic_place_id,
                ),
            )
        )

    def canonical_payload(self) -> dict[str, object]:
        """Return the serialization-independent payload used for hashing and sealing."""

        return {
            "manifest_version": self.manifest_version,
            "canonicalization_version": self.canonicalization_version,
            "members": [
                {
                    "synthetic_place_id": member.synthetic_place_id,
                    "split": member.split.value,
                }
                for member in self.canonical_members()
            ],
        }


class ManifestSeal(StrictContract):
    """Immutable integrity metadata for a single accepted manifest."""

    manifest_version: StableId
    canonicalization_version: Version
    manifest_sha256: Sha256
    sealed_at: datetime
    member_count: Annotated[int, Field(strict=True, ge=1)]
    dev_count: Annotated[int, Field(strict=True, ge=0)]
    blind_count: Annotated[int, Field(strict=True, ge=0)]

    @model_validator(mode="after")
    def enforce_seal_metadata(self) -> ManifestSeal:
        require_utc(self.sealed_at, field_name="sealed_at")
        if self.canonicalization_version != CANONICALIZATION_VERSION:
            raise ValueError("canonicalization_version must be canonical-json-v1")
        if (self.member_count, self.dev_count, self.blind_count) != (36, 24, 12):
            raise ValueError("seal counts must be exactly 36 total, 24 DEV, and 12 BLIND")
        return self
