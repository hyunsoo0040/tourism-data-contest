"""Human-sealed hard-duplicate authority for the canonical DEV-24 cohort."""

from __future__ import annotations

import os
import stat
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StrictContract, require_utc
from itda.domain.canonical import canonical_sha256

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
HARD_DUPLICATE_ADJUDICATION_PATH = (
    REPOSITORY_ROOT / "backend/schema/phase5_hard_duplicate_adjudication_v1.json"
)
HARD_DUPLICATE_ADJUDICATION_SHA256 = (
    "32905425be2491414797c0bdc026314de91cdd979abca7cd6d721df3370a8d22"
)
DEV_INPUT_AUTHORITY_SHA256 = "0dfa371289ba55ca14d99632915c3948269d7811645a759b618fed1957bfd3cc"
DEV_MEMBERSHIP_SHA256 = "979127c3cfd457fa0a9354acf7fd984c8d8b4d753a97c7c176ac531e0808af7a"
CATALOG_REVISION_SHA256 = "96dddd48d90b690ff6b5c9ce3f31f4f34f76ab0194ffcccc9803de608dbf812f"
CATALOG_APPROVAL_SHA256 = "c46a27466ef8c4778a427a0cff20766635401b5a21f69e224c8a75b0a6ddfe27"
CATALOG_ACTIVATION_EVENT_SHA256 = "db6b24df96c8d804b697bee7e8495ecd6a1afb729cc0cf127d53522f7b25d39b"
RELATIONSHIP_AUTOMATIC_ROOT_SHA256 = (
    "2d744a3a6cc19b5522364f5fa60c453b4197e6339970d705002561f7b4416fdf"
)
RELATIONSHIP_UNRESOLVED_ROOT_SHA256 = (
    "7a484e07675557eecc61eacab26290e43b2419fdd04445de165dcfd1c22f5cb5"
)
REVIEWED_RELATIONSHIP_LEAVES_ROOT_SHA256 = (
    "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
)
AUTHORITATIVE_RELATIONSHIP_LEAVES_SHA256 = (
    "b91084fdc4b881c53827b42e1e7434a494a402de0b58e391be3a16837a6f4b46"
)


class HardDuplicateClass(StrictContract):
    duplicate_group_id: Annotated[
        str,
        Field(strict=True, pattern=r"^hard-duplicate-singleton:[0-9a-f]{64}$"),
    ]
    member_place_ids: Annotated[tuple[str, ...], Field(min_length=1, max_length=1)]

    @model_validator(mode="after")
    def validate_singleton_identity(self) -> Self:
        place_id = self.member_place_ids[0]
        if not place_id.startswith("place:") or len(place_id) != 70:
            raise ValueError("hard-duplicate singleton member must be one canonical place ID")
        if self.duplicate_group_id != f"hard-duplicate-singleton:{place_id.removeprefix('place:')}":
            raise ValueError("hard-duplicate singleton group identity drifted")
        return self


class RelationshipResolutionBinding(StrictContract):
    relationship_automatic_count: Literal[871] = 871
    relationship_unresolved_count: Literal[3] = 3
    reviewed_relationship_leaf_count: Literal[0] = 0
    hard_duplicate_relationship_count: Literal[0] = 0
    relationship_automatic_leaves_root_sha256: Sha256
    relationship_unresolved_leaves_root_sha256: Sha256
    reviewed_relationship_leaves_root_sha256: Sha256
    authoritative_relationship_leaves_sha256: Sha256
    final_resolution_state: Literal["ZERO_APPROVED_HARD_DUPLICATE_RELATIONSHIP_LEAVES"]
    unresolved_proposal_policy: Literal["NON_HARD_UNLESS_SEPARATELY_HUMAN_APPROVED"]


class HardDuplicateAdjudication(StrictContract):
    schema_version: Literal["itda.phase5-hard-duplicate-adjudication.v1"]
    scope: Literal["CANONICAL_DEV_24"]
    decision: Literal["ALL_DEV_PLACES_MUTUALLY_DISTINCT_SINGLETONS"]
    approver_id: Literal["project-user"]
    approver_decision_ref: Literal["phase05-code-review:WR-04:2026-08-11"]
    approved_at: datetime
    decision_statement: Literal[
        "All 24 DEV canonical places are mutually distinct singleton "
        "hard-duplicate equivalence classes."
    ]
    non_promotion_statement: Literal[
        "No unresolved relationship proposal is promoted to a hard duplicate."
    ]
    source_dev_authority_sha256: Sha256
    dev_membership_sha256: Sha256
    catalog_revision_sha256: Sha256
    catalog_approval_sha256: Sha256
    catalog_activation_event_sha256: Sha256
    relationship_resolution: RelationshipResolutionBinding
    equivalence_classes: Annotated[
        tuple[HardDuplicateClass, ...], Field(min_length=24, max_length=24)
    ]
    partition_sha256: Sha256
    approver_decision_sha256: Sha256
    adjudication_sha256: Sha256

    @model_validator(mode="after")
    def validate_human_seal(self) -> Self:
        approved_at = require_utc(self.approved_at, field_name="approved_at")
        classes = tuple(self.equivalence_classes)
        place_ids = tuple(row.member_place_ids[0] for row in classes)
        group_ids = tuple(row.duplicate_group_id for row in classes)
        if place_ids != tuple(sorted(place_ids)) or len(set(place_ids)) != 24:
            raise ValueError("hard-duplicate partition must cover sorted unique DEV-24 membership")
        if len(set(group_ids)) != 24:
            raise ValueError("hard-duplicate partition must contain 24 singleton classes")
        if self.dev_membership_sha256 != canonical_sha256(list(place_ids)):
            raise ValueError("hard-duplicate partition membership digest drifted")
        if self.partition_sha256 != canonical_sha256(
            [row.model_dump(mode="json") for row in classes]
        ):
            raise ValueError("hard-duplicate partition digest drifted")
        if (
            self.source_dev_authority_sha256 != DEV_INPUT_AUTHORITY_SHA256
            or self.dev_membership_sha256 != DEV_MEMBERSHIP_SHA256
            or self.catalog_revision_sha256 != CATALOG_REVISION_SHA256
            or self.catalog_approval_sha256 != CATALOG_APPROVAL_SHA256
            or self.catalog_activation_event_sha256 != CATALOG_ACTIVATION_EVENT_SHA256
            or self.relationship_resolution.relationship_automatic_leaves_root_sha256
            != RELATIONSHIP_AUTOMATIC_ROOT_SHA256
            or self.relationship_resolution.relationship_unresolved_leaves_root_sha256
            != RELATIONSHIP_UNRESOLVED_ROOT_SHA256
            or self.relationship_resolution.reviewed_relationship_leaves_root_sha256
            != REVIEWED_RELATIONSHIP_LEAVES_ROOT_SHA256
            or self.relationship_resolution.authoritative_relationship_leaves_sha256
            != AUTHORITATIVE_RELATIONSHIP_LEAVES_SHA256
        ):
            raise ValueError("hard-duplicate adjudication parent authority drifted")
        decision_payload = {
            "approver_id": self.approver_id,
            "approver_decision_ref": self.approver_decision_ref,
            "approved_at": approved_at.isoformat().replace("+00:00", "Z"),
            "decision": self.decision,
            "decision_statement": self.decision_statement,
            "non_promotion_statement": self.non_promotion_statement,
            "dev_membership_sha256": self.dev_membership_sha256,
            "partition_sha256": self.partition_sha256,
            "relationship_resolution": self.relationship_resolution.model_dump(mode="json"),
        }
        if self.approver_decision_sha256 != canonical_sha256(decision_payload):
            raise ValueError("hard-duplicate approver decision identity drifted")
        payload = self.model_dump(mode="json", exclude={"adjudication_sha256"})
        if self.adjudication_sha256 != canonical_sha256(payload):
            raise ValueError("hard-duplicate adjudication self-digest drifted")
        return self

    @property
    def group_id_by_place(self) -> dict[str, str]:
        return {row.member_place_ids[0]: row.duplicate_group_id for row in self.equivalence_classes}


def _read_fixed_artifact() -> bytes:
    descriptor = os.open(
        HARD_DUPLICATE_ADJUDICATION_PATH,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or not 0 < metadata.st_size <= 64 * 1024
        ):
            raise ValueError("hard-duplicate adjudication artifact is not a bounded regular file")
        payload = bytearray()
        while len(payload) < metadata.st_size:
            chunk = os.read(descriptor, min(65_536, metadata.st_size - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        if len(payload) != metadata.st_size or (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ValueError("hard-duplicate adjudication artifact read was incomplete")
        return bytes(payload)
    finally:
        os.close(descriptor)


def load_hard_duplicate_adjudication() -> HardDuplicateAdjudication:
    """Load the one repository-fixed human authority; callers cannot select inputs."""

    adjudication = HardDuplicateAdjudication.model_validate_json(_read_fixed_artifact())
    if adjudication.adjudication_sha256 != HARD_DUPLICATE_ADJUDICATION_SHA256:
        raise ValueError("hard-duplicate adjudication is not the fixed human decision")
    return adjudication


__all__ = [
    "HARD_DUPLICATE_ADJUDICATION_SHA256",
    "HardDuplicateAdjudication",
    "HardDuplicateClass",
    "RelationshipResolutionBinding",
    "load_hard_duplicate_adjudication",
]
