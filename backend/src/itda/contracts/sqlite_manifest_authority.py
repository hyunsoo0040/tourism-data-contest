"""Isolated SQLite logical-schema and empty-projection authority contracts."""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import date, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal, Self, cast

from pydantic import Field, field_validator, model_validator

from itda.contracts.authority import (
    AuthorityIssuanceContext,
    freeze_issuance_context,
    validate_authority_token,
)
from itda.contracts.base import Sha256, StrictContract, require_utc
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

APPLICATION_ID: Literal[1_230_259_265] = 1_230_259_265
APPLICATION_ID_HEX: Literal["0x49544441"] = "0x49544441"
APPLICATION_ID_REGISTRY_SHA256 = "d8e4f2aba3ade893536b17db3f390ade9c27fbb1246e8650a0d0a444f2282181"
RESEARCH_ATTESTATION_SHA256 = "db67bf0ac14996cf3328c870f1a0addb15eb8ebb8b7ff2417c0f40132f703ec9"
APPLICATION_ID_SOURCE_URL = "https://www.sqlite.org/src/raw/magic.txt?ci=trunk"
APPLICATION_ID_RETRIEVED_ON = date(2026, 8, 2)
RESEARCH_VALID_THROUGH = date(2026, 9, 1)
SQLITE_USER_VERSION: Literal[1] = 1
SCHEMA_VERSION: Literal["itda.evaluation-manifest-sqlite-schema.v1"] = (
    "itda.evaluation-manifest-sqlite-schema.v1"
)
DDL_RELPATH: Literal["backend/schema/evaluation_manifest_v1/schema.sql"] = (
    "backend/schema/evaluation_manifest_v1/schema.sql"
)
REGISTRY_RELPATH = "backend/schema/evaluation_manifest_v1/sqlite-application-ids-2026-08-02.txt"
EMPTY_DATABASE_RELPATH: Literal["backend/schema/evaluation_manifest_v1/empty.sqlite3"] = (
    "backend/schema/evaluation_manifest_v1/empty.sqlite3"
)
LOGICAL_MANIFEST_RELPATH: Literal[
    "backend/schema/evaluation_manifest_v1/logical-schema-manifest.json"
] = "backend/schema/evaluation_manifest_v1/logical-schema-manifest.json"
EXPECTED_TABLES: tuple[
    Literal[
        "artifact_metadata",
        "authority_consumptions",
        "manifest_members",
        "manifest_seals",
    ],
    ...,
] = (
    "artifact_metadata",
    "authority_consumptions",
    "manifest_members",
    "manifest_seals",
)
SIDECAR_SUFFIXES = ("-journal", "-wal", "-shm")
INITIALIZATION_ACTION: Literal["sqlite-manifest-initialize"] = "sqlite-manifest-initialize"
INITIALIZATION_RESTRICTED_ROOT: Literal["artifacts/restricted/catalog/v2/sqlite"] = (
    "artifacts/restricted/catalog/v2/sqlite"
)
INITIALIZATION_DATABASE_NAME: Literal["evaluation-authority.sqlite3"] = (
    "evaluation-authority.sqlite3"
)
INITIALIZATION_EMPTY_COUNTS: dict[str, int] = {
    "authority_consumptions": 0,
    "manifest_members": 0,
    "manifest_seals": 0,
}
SEAL_ACTION: Literal["sqlite-real-manifest-seal"] = "sqlite-real-manifest-seal"
SEAL_MANIFEST_VERSION: Literal["catalog-v2-real-split-v1"] = "catalog-v2-real-split-v1"
SEAL_COUNTS: dict[str, int] = {"blind": 12, "dev": 24, "total": 36}
SEAL_EMPTY_COUNTS: dict[str, int] = {
    "authority_consumptions": 0,
    "manifest_members": 0,
    "manifest_seals": 0,
}
_DEFAULT_REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
_DEFAULT_RESEARCH_PATH = (
    _DEFAULT_REPOSITORY_ROOT
    / ".planning/phases/02-canonical-36-rights-and-evaluation-manifest"
    / "02-SQLITE-TRANSITION-RESEARCH.md"
)

_ROOT_PATTERN = re.compile(r"^0\s+string\s+=SQLite\\ format\\ 3$")
_FALLBACK_PATTERN = re.compile(r"^>0\s+string\s+=SQLite\s+SQLite3 database$")
_REGISTRY_ROW_PATTERN = re.compile(
    r"^>(?P<offset>60|68)\s+belong\s+=0x(?P<value>[0-9a-f]{8})\s+"
    r"(?P<description>[^\x00-\x1f\x7f]+)$"
)
_RESEARCH_VALIDITY_PATTERN = re.compile(r"\*\*Valid until:\*\* 2026-09-01\b")


class SQLiteManifestAuthorityError(ValueError):
    """A SQLite authority artifact failed a closed integrity contract."""


class ApplicationIdCollisionProof(StrictContract):
    """Membership-free evidence for one offline SQLite application-id decision."""

    schema_version: Literal["itda.sqlite-application-id-collision-proof.v1"] = (
        "itda.sqlite-application-id-collision-proof.v1"
    )
    source_url: Literal["https://www.sqlite.org/src/raw/magic.txt?ci=trunk"] = (
        "https://www.sqlite.org/src/raw/magic.txt?ci=trunk"
    )
    retrieved_on: date = APPLICATION_ID_RETRIEVED_ON
    registry_path: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=240, pattern=r"^[A-Za-z0-9._/-]+$"),
    ]
    application_id_registry_sha256: Sha256
    research_attestation_sha256: Sha256
    application_id: Literal[1_230_259_265] = 1_230_259_265
    application_id_hex: Literal["0x49544441"] = "0x49544441"
    parsed_application_id_count: Annotated[int, Field(strict=True, ge=1)]
    valid_through: date = RESEARCH_VALID_THROUGH
    status: Literal["ABSENT"] = "ABSENT"
    application_id_collision: Literal[False] = False
    proof_sha256: Sha256 | None = None

    @field_validator("retrieved_on")
    @classmethod
    def retrieved_on_must_match_snapshot(cls, value: date) -> date:
        if value != APPLICATION_ID_RETRIEVED_ON:
            raise ValueError("retrieved_on does not match the vendored snapshot")
        return value

    @field_validator("valid_through")
    @classmethod
    def valid_through_must_match_research(cls, value: date) -> date:
        if value != RESEARCH_VALID_THROUGH:
            raise ValueError("valid_through does not match the research attestation")
        return value

    @field_validator("registry_path")
    @classmethod
    def registry_path_must_be_canonical_relative(cls, value: str) -> str:
        path = Path(value)
        if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
            raise ValueError("registry_path must be a canonical repository-relative path")
        return value

    @model_validator(mode="after")
    def validate_proof_hash(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"proof_sha256"}, mode="json"))
        if self.proof_sha256 is None:
            object.__setattr__(self, "proof_sha256", expected)
        elif not hmac.compare_digest(self.proof_sha256, expected):
            raise ValueError("application-id collision proof digest is stale")
        return self


class SQLiteSchemaObject(StrictContract):
    """One normalized non-internal sqlite_schema object."""

    object_type: Literal["table", "index", "trigger", "view"]
    name: Annotated[str, Field(strict=True, min_length=1, max_length=128)]
    table_name: Annotated[str, Field(strict=True, min_length=1, max_length=128)]
    sql: Annotated[str, Field(strict=True, min_length=1, max_length=16_384)]


class SQLiteColumn(StrictContract):
    """Normalized PRAGMA table_info row."""

    cid: Annotated[int, Field(strict=True, ge=0)]
    name: Annotated[str, Field(strict=True, min_length=1, max_length=128)]
    declared_type: Annotated[str, Field(strict=True, min_length=1, max_length=128)]
    not_null: Literal[0, 1]
    default_sql: str | None
    primary_key_ordinal: Annotated[int, Field(strict=True, ge=0)]


class SQLiteForeignKey(StrictContract):
    """Normalized PRAGMA foreign_key_list row."""

    foreign_key_id: Annotated[int, Field(strict=True, ge=0)]
    sequence: Annotated[int, Field(strict=True, ge=0)]
    referenced_table: Annotated[str, Field(strict=True, min_length=1, max_length=128)]
    from_column: Annotated[str, Field(strict=True, min_length=1, max_length=128)]
    to_column: Annotated[str, Field(strict=True, min_length=1, max_length=128)]
    on_update: Annotated[str, Field(strict=True, min_length=1, max_length=32)]
    on_delete: Annotated[str, Field(strict=True, min_length=1, max_length=32)]
    match: Annotated[str, Field(strict=True, min_length=1, max_length=32)]


class SQLiteIndexColumn(StrictContract):
    """Normalized PRAGMA index_xinfo row."""

    sequence: Annotated[int, Field(strict=True, ge=0)]
    column_id: int
    column_name: str | None
    descending: Literal[0, 1]
    collation: str | None
    key_column: Literal[0, 1]


class SQLiteIndex(StrictContract):
    """Normalized PRAGMA index_list plus index_xinfo evidence."""

    name: Annotated[str, Field(strict=True, min_length=1, max_length=128)]
    unique: Literal[0, 1]
    origin: Literal["c", "u", "pk"]
    partial: Literal[0, 1]
    columns: tuple[SQLiteIndexColumn, ...]


def _validate_required_pragmas(value: dict[str, int | str]) -> dict[str, int | str]:
    expected: dict[str, int | str] = {
        "foreign_keys": 1,
        "journal_mode": "delete",
        "trusted_schema": 0,
    }
    if value != expected:
        raise ValueError("required_pragmas are not the exact SQLite authority policy")
    return value


def _validate_effective_pragmas(value: dict[str, int | str]) -> dict[str, int | str]:
    expected: dict[str, int | str] = {
        "foreign_keys": 1,
        "journal_mode": "delete",
        "query_only": 1,
        "trusted_schema": 0,
    }
    if value != expected:
        raise ValueError("effective_pragmas do not match the read-only authority policy")
    return value


class SQLiteLogicalSchemaManifest(StrictContract):
    """Authoritative normalized schema independent of physical SQLite layout."""

    schema_version: Literal["itda.evaluation-manifest-sqlite-schema.v1"] = SCHEMA_VERSION
    ddl_path: Literal["backend/schema/evaluation_manifest_v1/schema.sql"] = DDL_RELPATH
    ddl_sha256: Sha256
    application_id: Literal[1_230_259_265] = APPLICATION_ID
    application_id_hex: Literal["0x49544441"] = APPLICATION_ID_HEX
    user_version: Literal[1] = SQLITE_USER_VERSION
    required_pragmas: dict[str, int | str]
    application_id_collision_proof: ApplicationIdCollisionProof
    ordered_schema_objects: tuple[SQLiteSchemaObject, ...]
    table_columns: dict[str, tuple[SQLiteColumn, ...]]
    foreign_keys: dict[str, tuple[SQLiteForeignKey, ...]]
    indexes: dict[str, tuple[SQLiteIndex, ...]]
    empty_tables: tuple[
        Literal[
            "artifact_metadata",
            "authority_consumptions",
            "manifest_members",
            "manifest_seals",
        ],
        ...,
    ] = EXPECTED_TABLES
    logical_schema_authoritative: Literal[True] = True
    logical_schema_sha256: Sha256 | None = None

    _required_pragmas_are_exact = field_validator("required_pragmas")(_validate_required_pragmas)

    def logical_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "ddl_sha256": self.ddl_sha256,
            "application_id": self.application_id,
            "application_id_hex": self.application_id_hex,
            "user_version": self.user_version,
            "required_pragmas": self.required_pragmas,
            "ordered_schema_objects": [
                row.model_dump(mode="json") for row in self.ordered_schema_objects
            ],
            "table_columns": {
                table: [row.model_dump(mode="json") for row in rows]
                for table, rows in sorted(self.table_columns.items())
            },
            "foreign_keys": {
                table: [row.model_dump(mode="json") for row in rows]
                for table, rows in sorted(self.foreign_keys.items())
            },
            "indexes": {
                table: [row.model_dump(mode="json") for row in rows]
                for table, rows in sorted(self.indexes.items())
            },
            "empty_tables": list(self.empty_tables),
        }

    @model_validator(mode="after")
    def validate_logical_schema_hash(self) -> Self:
        if tuple(sorted(self.table_columns)) != EXPECTED_TABLES:
            raise ValueError("logical schema table inventory is not exact")
        if tuple(sorted(self.foreign_keys)) != EXPECTED_TABLES:
            raise ValueError("logical schema foreign-key inventory is not exact")
        if tuple(sorted(self.indexes)) != EXPECTED_TABLES:
            raise ValueError("logical schema index inventory is not exact")
        expected = canonical_sha256(self.logical_payload())
        if self.logical_schema_sha256 is None:
            object.__setattr__(self, "logical_schema_sha256", expected)
        elif not hmac.compare_digest(self.logical_schema_sha256, expected):
            raise ValueError("logical schema digest is stale")
        return self


class SQLiteFileIdentity(StrictContract):
    """Exact physical identity of the tracked convenience projection."""

    relative_path: Literal["backend/schema/evaluation_manifest_v1/empty.sqlite3"] = (
        EMPTY_DATABASE_RELPATH
    )
    sha256: Sha256
    size_bytes: Annotated[int, Field(strict=True, gt=0)]
    sqlite_header_hex: Literal["53514c69746520666f726d6174203300"] = (
        "53514c69746520666f726d6174203300"
    )


class SQLiteEmptyProof(StrictContract):
    """Independent zero-row, logical-schema, file, and sidecar proof."""

    schema_version: Literal["itda.sqlite-empty-projection-proof.v1"] = (
        "itda.sqlite-empty-projection-proof.v1"
    )
    ddl_sha256: Sha256
    logical_schema_manifest_path: Literal[
        "backend/schema/evaluation_manifest_v1/logical-schema-manifest.json"
    ] = LOGICAL_MANIFEST_RELPATH
    logical_schema_manifest_sha256: Sha256
    logical_schema_sha256: Sha256
    application_id_collision_proof: ApplicationIdCollisionProof
    application_id: Literal[1_230_259_265] = APPLICATION_ID
    user_version: Literal[1] = SQLITE_USER_VERSION
    sqlite_version: Annotated[str, Field(strict=True, min_length=1, max_length=64)]
    effective_pragmas: dict[str, int | str]
    empty_file_identity: SQLiteFileIdentity
    empty_file_sha256: Sha256
    empty_file_size_bytes: Annotated[int, Field(strict=True, gt=0)]
    binary_authoritative: Literal[False] = False
    schema_object_sha256: Sha256
    row_counts: dict[str, int]
    freelist_count: Literal[0] = 0
    integrity_check: Literal["ok"] = "ok"
    foreign_key_check_count: Literal[0] = 0
    sqlite_sequence_present: Literal[False] = False
    unexpected_schema_objects: tuple[str, ...] = ()
    sidecars: dict[str, bool]
    proof_sha256: Sha256 | None = None

    _effective_pragmas_are_exact = field_validator("effective_pragmas")(_validate_effective_pragmas)

    @model_validator(mode="after")
    def validate_empty_proof(self) -> Self:
        expected_counts = {table: 0 for table in EXPECTED_TABLES}
        if self.row_counts != expected_counts:
            raise ValueError("empty projection row counts are not exactly zero")
        if self.sidecars != {"journal": False, "shm": False, "wal": False}:
            raise ValueError("empty projection sidecar proof is not exact")
        if not hmac.compare_digest(
            self.empty_file_identity.sha256,
            self.empty_file_sha256,
        ):
            raise ValueError("empty file identity digest does not match proof")
        if self.empty_file_identity.size_bytes != self.empty_file_size_bytes:
            raise ValueError("empty file identity size does not match proof")
        expected = canonical_sha256(self.model_dump(exclude={"proof_sha256"}, mode="json"))
        if self.proof_sha256 is None:
            object.__setattr__(self, "proof_sha256", expected)
        elif not hmac.compare_digest(self.proof_sha256, expected):
            raise ValueError("empty projection proof digest is stale")
        return self


class SQLiteInitializationState(StrictContract):
    """Protected membership-free attestation for one empty initialization."""

    schema_version: Literal["itda.sqlite-initialization-state.v1"] = (
        "itda.sqlite-initialization-state.v1"
    )
    action: Literal["sqlite-manifest-initialize"] = INITIALIZATION_ACTION
    split_approval_path: Literal[
        "artifacts/restricted/catalog/v2/split/real-split-approval.json"
    ] = "artifacts/restricted/catalog/v2/split/real-split-approval.json"
    split_approval_sha256: Sha256
    split_approval_receipt_sha256: Sha256
    split_approval_status: Literal["APPROVED_UNSEALED"] = "APPROVED_UNSEALED"
    ddl_sha256: Sha256
    logical_schema_manifest_sha256: Sha256
    logical_schema_sha256: Sha256
    empty_proof_sha256: Sha256
    tracked_empty_file_sha256: Sha256
    restricted_root: Literal["artifacts/restricted/catalog/v2/sqlite"] = (
        INITIALIZATION_RESTRICTED_ROOT
    )
    directory_mode: Literal["0700"] = "0700"
    database_mode: Literal["0600"] = "0600"
    empty_counts: dict[str, int]
    target_absent: Literal[True] = True
    membership_present: Literal[False] = False
    prepared_at: datetime
    state_attestation_sha256: Sha256 | None = None

    @field_validator("prepared_at")
    @classmethod
    def prepared_at_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="prepared_at")

    @field_validator("empty_counts")
    @classmethod
    def empty_counts_are_exact(cls, value: dict[str, int]) -> dict[str, int]:
        if value != INITIALIZATION_EMPTY_COUNTS:
            raise ValueError("initialization state empty counts are not exact")
        return value

    @model_validator(mode="after")
    def validate_state_hash(self) -> Self:
        expected = canonical_sha256(
            self.model_dump(exclude={"state_attestation_sha256"}, mode="json")
        )
        if self.state_attestation_sha256 is None:
            object.__setattr__(self, "state_attestation_sha256", expected)
        elif not hmac.compare_digest(self.state_attestation_sha256, expected):
            raise ValueError("initialization state attestation digest is stale")
        return self


class SQLiteInitializationRequest(StrictContract):
    """Public membership-free request for one exact restricted empty file."""

    schema_version: Literal["itda.sqlite-initialization-request.v1"] = (
        "itda.sqlite-initialization-request.v1"
    )
    action: Literal["sqlite-manifest-initialize"] = INITIALIZATION_ACTION
    request_sha256: Sha256 | None = None
    state_attestation_sha256: Sha256
    target_sha256: Sha256
    binding_sha256: Sha256
    ddl_sha256: Sha256
    logical_schema_manifest_sha256: Sha256
    logical_schema_sha256: Sha256
    empty_proof_sha256: Sha256
    restricted_root: Literal["artifacts/restricted/catalog/v2/sqlite"] = (
        INITIALIZATION_RESTRICTED_ROOT
    )
    directory_mode: Literal["0700"] = "0700"
    database_mode: Literal["0600"] = "0600"
    database_filename_sha256: Sha256
    empty_counts: dict[str, int]
    canonical_ddl_source: Literal[True] = True
    tracked_empty_projection_source: Literal[False] = False
    target_preexisting: Literal[False] = False
    membership_present: Literal[False] = False
    sidecars_expected: Literal[False] = False
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at")
    @classmethod
    def timestamps_must_be_utc(cls, value: datetime, info: Any) -> datetime:
        return require_utc(value, field_name=str(info.field_name))

    @field_validator("empty_counts")
    @classmethod
    def request_empty_counts_are_exact(cls, value: dict[str, int]) -> dict[str, int]:
        if value != INITIALIZATION_EMPTY_COUNTS:
            raise ValueError("initialization request empty counts are not exact")
        return value

    @model_validator(mode="after")
    def validate_request(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("initialization request expiry must follow issuance")
        expected = canonical_sha256(self.model_dump(exclude={"request_sha256"}, mode="json"))
        if self.request_sha256 is None:
            object.__setattr__(self, "request_sha256", expected)
        elif not hmac.compare_digest(self.request_sha256, expected):
            raise ValueError("initialization request digest is stale")
        return self


class SQLiteRestrictedFileIdentity(StrictContract):
    """Sanitized identity of the restricted empty database instance."""

    relative_path: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            max_length=300,
            pattern=(
                r"^artifacts/restricted/catalog/v2/sqlite/releases/"
                r"[0-9a-f]{64}/evaluation-authority\.sqlite3$"
            ),
        ),
    ]
    sha256: Sha256
    size_bytes: Annotated[int, Field(strict=True, gt=0)]
    device: Annotated[int, Field(strict=True, ge=0)]
    inode: Annotated[int, Field(strict=True, gt=0)]
    uid: Annotated[int, Field(strict=True, ge=0)]
    mode: Literal["0600"] = "0600"
    link_count: Literal[1] = 1
    no_follow_result: Literal["LSTAT_OPEN_FSTAT_MATCH"] = "LSTAT_OPEN_FSTAT_MATCH"


class SQLiteInitializationReceipt(StrictContract):
    """Sanitized proof of one authorized schema-only initialization."""

    schema_version: Literal["itda.sqlite-initialization-receipt.v1"] = (
        "itda.sqlite-initialization-receipt.v1"
    )
    action: Literal["sqlite-manifest-initialize"] = INITIALIZATION_ACTION
    request_sha256: Sha256
    state_attestation_sha256: Sha256
    target_sha256: Sha256
    binding_sha256: Sha256
    token_sha256: Sha256
    nonce_sha256: Sha256
    issuance_context_sha256: Sha256
    ddl_sha256: Sha256
    logical_schema_manifest_sha256: Sha256
    logical_schema_sha256: Sha256
    empty_proof_sha256: Sha256
    sqlite_version: Annotated[str, Field(strict=True, min_length=1, max_length=64)]
    application_id: Literal[1_230_259_265] = APPLICATION_ID
    user_version: Literal[1] = SQLITE_USER_VERSION
    effective_pragmas: dict[str, int | str]
    empty_counts: dict[str, int]
    freelist_count: Literal[0] = 0
    integrity_check: Literal["ok"] = "ok"
    foreign_key_check_count: Literal[0] = 0
    sidecars: dict[str, bool]
    file_identity: SQLiteRestrictedFileIdentity
    directory_mode: Literal["0700"] = "0700"
    publication_disposition: Literal["CREATED"] = "CREATED"
    initialized_at: datetime
    receipt_sha256: Sha256 | None = None

    _effective_pragmas_are_exact = field_validator("effective_pragmas")(_validate_effective_pragmas)

    @field_validator("initialized_at")
    @classmethod
    def initialized_at_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="initialized_at")

    @field_validator("empty_counts")
    @classmethod
    def receipt_empty_counts_are_exact(cls, value: dict[str, int]) -> dict[str, int]:
        if value != INITIALIZATION_EMPTY_COUNTS:
            raise ValueError("initialization receipt empty counts are not exact")
        return value

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        if self.sidecars != {"journal": False, "shm": False, "wal": False}:
            raise ValueError("initialization receipt sidecar proof is not exact")
        expected = canonical_sha256(self.model_dump(exclude={"receipt_sha256"}, mode="json"))
        if self.receipt_sha256 is None:
            object.__setattr__(self, "receipt_sha256", expected)
        elif not hmac.compare_digest(self.receipt_sha256, expected):
            raise ValueError("initialization receipt digest is stale")
        return self


class SQLiteSealClassification(StrEnum):
    """Closed real-manifest relation states used before any seal branch."""

    EXACT_UNSEALED = "EXACT_UNSEALED"
    EXACT_COMMITTED = "EXACT_COMMITTED"
    PARTIAL = "PARTIAL"
    CONFLICTING = "CONFLICTING"


class SQLiteSealReadiness(StrictContract):
    """Sanitized proof that the exact initialized authority remains empty."""

    schema_version: Literal["itda.sqlite-seal-readiness.v1"] = "itda.sqlite-seal-readiness.v1"
    status: Literal["EXACT_UNSEALED"] = "EXACT_UNSEALED"
    initialization_receipt_sha256: Sha256
    initialization_receipt_receipt_sha256: Sha256
    initialized_file_sha256: Sha256
    ddl_sha256: Sha256
    logical_schema_manifest_sha256: Sha256
    logical_schema_sha256: Sha256
    split_approval_sha256: Sha256
    split_approval_receipt_sha256: Sha256
    empty_counts: dict[str, int]
    effective_pragmas: dict[str, int | str]
    sidecars: dict[str, bool]
    file_identity: SQLiteRestrictedFileIdentity
    same_uid_root_residual: Literal[True] = True
    readiness_sha256: Sha256 | None = None

    _effective_pragmas_are_exact = field_validator("effective_pragmas")(_validate_effective_pragmas)

    @field_validator("empty_counts")
    @classmethod
    def readiness_counts_are_exact(cls, value: dict[str, int]) -> dict[str, int]:
        if value != SEAL_EMPTY_COUNTS:
            raise ValueError("seal readiness counts are not exactly empty")
        return value

    @field_validator("sidecars")
    @classmethod
    def readiness_sidecars_are_exact(cls, value: dict[str, bool]) -> dict[str, bool]:
        if value != {"journal": False, "shm": False, "wal": False}:
            raise ValueError("seal readiness sidecar state is not exact")
        return value

    @model_validator(mode="after")
    def validate_readiness_hash(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"readiness_sha256"}, mode="json"))
        if self.readiness_sha256 is None:
            object.__setattr__(self, "readiness_sha256", expected)
        elif not hmac.compare_digest(self.readiness_sha256, expected):
            raise ValueError("seal readiness digest is stale")
        return self


class SQLiteSealState(StrictContract):
    """Membership-free closed classification of the live seal relation."""

    schema_version: Literal["itda.sqlite-seal-state.v1"] = "itda.sqlite-seal-state.v1"
    classification: Literal[
        SQLiteSealClassification.EXACT_UNSEALED,
        SQLiteSealClassification.EXACT_COMMITTED,
        SQLiteSealClassification.PARTIAL,
        SQLiteSealClassification.CONFLICTING,
    ]
    manifest_version: Annotated[str, Field(strict=True, min_length=1, max_length=128)]
    expected_request_sha256: Sha256
    expected_nonce_sha256: Sha256
    expected_logical_seal_sha256: Sha256
    counts: dict[str, int]
    relation_sha256: Sha256
    state_sha256: Sha256 | None = None

    @field_validator("counts")
    @classmethod
    def counts_use_exact_inventory(cls, value: dict[str, int]) -> dict[str, int]:
        if set(value) != {
            "authority_consumptions",
            "manifest_members",
            "manifest_seals",
        } or any(
            not isinstance(count, int) or isinstance(count, bool) or count < 0
            for count in value.values()
        ):
            raise ValueError("seal state counts are malformed")
        return value

    @model_validator(mode="after")
    def validate_state_hash(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"state_sha256"}, mode="json"))
        if self.state_sha256 is None:
            object.__setattr__(self, "state_sha256", expected)
        elif not hmac.compare_digest(self.state_sha256, expected):
            raise ValueError("seal state digest is stale")
        return self


def _validate_seal_counts(value: dict[str, int]) -> dict[str, int]:
    if value != SEAL_COUNTS:
        raise ValueError("seal counts must be exactly DEV-24/BLIND-12/total-36")
    return value


class SQLiteSealAuthorityState(StrictContract):
    """Protected, membership-free parents for one exact seal request."""

    schema_version: Literal["itda.sqlite-real-manifest-seal-state.v1"] = (
        "itda.sqlite-real-manifest-seal-state.v1"
    )
    status: Literal["EXACT_UNSEALED"] = "EXACT_UNSEALED"
    manifest_version: Literal["catalog-v2-real-split-v1"] = SEAL_MANIFEST_VERSION
    readiness_sha256: Sha256
    initialization_receipt_sha256: Sha256
    initialized_file_sha256: Sha256
    ddl_sha256: Sha256
    logical_schema_manifest_sha256: Sha256
    logical_schema_sha256: Sha256
    catalog_revision_sha256: Sha256
    catalog_activation_sha256: Sha256
    active_bindings_sha256: Sha256
    split_approval_sha256: Sha256
    split_approval_receipt_sha256: Sha256
    split_manifest_sha256: Sha256
    determinism_report_sha256: Sha256
    split_replay_sha256: Sha256
    membership_sha256: Sha256
    logical_seal_input_sha256: Sha256
    counts: dict[str, int]
    prepared_at: datetime
    state_attestation_sha256: Sha256 | None = None

    _counts_are_exact = field_validator("counts")(_validate_seal_counts)

    @field_validator("prepared_at")
    @classmethod
    def prepared_at_is_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="prepared_at")

    @model_validator(mode="after")
    def validate_state_attestation(self) -> Self:
        expected = canonical_sha256(
            self.model_dump(exclude={"state_attestation_sha256"}, mode="json")
        )
        if self.state_attestation_sha256 is None:
            object.__setattr__(self, "state_attestation_sha256", expected)
        elif not hmac.compare_digest(self.state_attestation_sha256, expected):
            raise ValueError("seal authority state attestation is stale")
        return self


class SQLiteSealRequest(StrictContract):
    """Public digest/count-only request for one exact real-manifest seal."""

    schema_version: Literal["itda.sqlite-real-manifest-seal-request.v1"] = (
        "itda.sqlite-real-manifest-seal-request.v1"
    )
    action: Literal["sqlite-real-manifest-seal"] = SEAL_ACTION
    request_sha256: Sha256 | None = None
    state_attestation_sha256: Sha256
    target_sha256: Sha256
    binding_sha256: Sha256
    reviewer_id: Annotated[
        str,
        Field(strict=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"),
    ]
    manifest_version: Literal["catalog-v2-real-split-v1"] = SEAL_MANIFEST_VERSION
    initialization_receipt_sha256: Sha256
    initialized_file_sha256: Sha256
    ddl_sha256: Sha256
    logical_schema_manifest_sha256: Sha256
    logical_schema_sha256: Sha256
    catalog_revision_sha256: Sha256
    catalog_activation_sha256: Sha256
    split_approval_sha256: Sha256
    split_approval_receipt_sha256: Sha256
    split_manifest_sha256: Sha256
    determinism_report_sha256: Sha256
    membership_sha256: Sha256
    logical_seal_input_sha256: Sha256
    nonce_sha256: Sha256
    counts: dict[str, int]
    issued_at: datetime
    expires_at: datetime

    _counts_are_exact = field_validator("counts")(_validate_seal_counts)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def request_timestamps_are_utc(cls, value: datetime, info: Any) -> datetime:
        return require_utc(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def validate_request_hash(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("seal request expiry must follow issuance")
        expected = canonical_sha256(self.model_dump(exclude={"request_sha256"}, mode="json"))
        if self.request_sha256 is None:
            object.__setattr__(self, "request_sha256", expected)
        elif not hmac.compare_digest(self.request_sha256, expected):
            raise ValueError("seal request digest is stale")
        return self


class SQLiteSealReceipt(StrictContract):
    """Sanitized Plan 59 receipt contract, defined early for closed verification."""

    schema_version: Literal["itda.sqlite-real-manifest-seal-receipt.v1"] = (
        "itda.sqlite-real-manifest-seal-receipt.v1"
    )
    action: Literal["sqlite-real-manifest-seal"] = SEAL_ACTION
    request_sha256: Sha256
    state_attestation_sha256: Sha256
    target_sha256: Sha256
    binding_sha256: Sha256
    token_sha256: Sha256
    nonce_sha256: Sha256
    initialization_receipt_sha256: Sha256
    initialized_file_sha256: Sha256
    ddl_sha256: Sha256
    logical_schema_manifest_sha256: Sha256
    logical_schema_sha256: Sha256
    catalog_revision_sha256: Sha256
    catalog_activation_sha256: Sha256
    split_approval_sha256: Sha256
    split_approval_receipt_sha256: Sha256
    split_manifest_sha256: Sha256
    determinism_report_sha256: Sha256
    membership_sha256: Sha256
    logical_seal_input_sha256: Sha256
    logical_seal_sha256: Sha256
    database_sha256: Sha256
    database_size_bytes: Annotated[int, Field(strict=True, ge=1)]
    database_uid: Annotated[int, Field(strict=True, ge=0)]
    database_mode: Literal["0600"] = "0600"
    database_link_count: Literal[1] = 1
    no_follow_result: Literal["LSTAT_OPEN_FSTAT_MATCH"] = "LSTAT_OPEN_FSTAT_MATCH"
    sqlite_version: Annotated[str, Field(strict=True, min_length=1, max_length=32)]
    effective_pragmas: dict[str, int | str]
    integrity_check: Literal["ok"] = "ok"
    foreign_key_check_count: Literal[0] = 0
    sidecars: dict[str, bool]
    counts: dict[str, int]
    publication_disposition: Literal["PUBLISHED", "ALREADY_COMMITTED_VERIFIED"]
    sealed_at: datetime
    receipt_sha256: Sha256 | None = None

    _counts_are_exact = field_validator("counts")(_validate_seal_counts)
    _effective_pragmas_are_exact = field_validator("effective_pragmas")(_validate_effective_pragmas)

    @field_validator("sidecars")
    @classmethod
    def receipt_sidecars_are_exact(cls, value: dict[str, bool]) -> dict[str, bool]:
        if value != {"journal": False, "shm": False, "wal": False}:
            raise ValueError("seal receipt sidecar state is not exact")
        return value

    @field_validator("sealed_at")
    @classmethod
    def sealed_at_is_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="sealed_at")

    @model_validator(mode="after")
    def validate_receipt_hash(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"receipt_sha256"}, mode="json"))
        if self.receipt_sha256 is None:
            object.__setattr__(self, "receipt_sha256", expected)
        elif not hmac.compare_digest(self.receipt_sha256, expected):
            raise ValueError("seal receipt digest is stale")
        return self


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _read_utf8_lf(path: Path, *, label: str) -> tuple[bytes, str]:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise SQLiteManifestAuthorityError(f"{label} could not be read") from exc
    if b"\r" in payload or b"\x00" in payload:
        raise SQLiteManifestAuthorityError(f"{label} is not canonical UTF-8/LF text")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise SQLiteManifestAuthorityError(f"{label} is not strict UTF-8") from exc
    return payload, text


def _parse_application_id_registry(text: str) -> tuple[int, ...]:
    root_count = 0
    fallback_count = 0
    rows: dict[tuple[int, int], str] = {}
    application_ids: list[int] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line or line.startswith("#"):
            continue
        if _ROOT_PATTERN.fullmatch(line):
            root_count += 1
            continue
        if _FALLBACK_PATTERN.fullmatch(line):
            fallback_count += 1
            continue
        match = _REGISTRY_ROW_PATTERN.fullmatch(line)
        if match is None:
            raise SQLiteManifestAuthorityError(
                f"application-id registry contains malformed row at line {line_number}"
            )
        offset = int(match.group("offset"))
        value = int(match.group("value"), 16)
        key = (offset, value)
        if key in rows:
            raise SQLiteManifestAuthorityError("application-id registry contains duplicate row")
        rows[key] = match.group("description")
        if offset == 68:
            application_ids.append(value)
    if root_count != 1 or fallback_count != 1 or not application_ids:
        raise SQLiteManifestAuthorityError("application-id registry framing is malformed")
    return tuple(application_ids)


def verify_application_id_collision(
    registry_path: Path,
    *,
    research_path: Path,
    expected_registry_sha256: str = APPLICATION_ID_REGISTRY_SHA256,
    expected_research_sha256: str = RESEARCH_ATTESTATION_SHA256,
    as_of: date,
    registry_repo_relative_path: str | None = None,
    network_capability: object | None = None,
) -> ApplicationIdCollisionProof:
    """Verify the pinned registry and research bytes entirely offline."""

    if network_capability is not None:
        raise SQLiteManifestAuthorityError("network capability is forbidden for collision proof")
    registry_bytes, registry_text = _read_utf8_lf(
        registry_path,
        label="application-id registry",
    )
    registry_sha256 = _sha256(registry_bytes)
    if not hmac.compare_digest(registry_sha256, expected_registry_sha256):
        raise SQLiteManifestAuthorityError("application-id registry digest drift")
    research_bytes, research_text = _read_utf8_lf(
        research_path,
        label="research attestation",
    )
    research_sha256 = _sha256(research_bytes)
    if not hmac.compare_digest(research_sha256, expected_research_sha256):
        raise SQLiteManifestAuthorityError("research attestation digest drift")
    if _RESEARCH_VALIDITY_PATTERN.search(research_text) is None:
        raise SQLiteManifestAuthorityError("research attestation validity is malformed")
    if as_of > RESEARCH_VALID_THROUGH:
        raise SQLiteManifestAuthorityError("application-id collision evidence expired")

    application_ids = _parse_application_id_registry(registry_text)
    if APPLICATION_ID in application_ids:
        raise SQLiteManifestAuthorityError("application-id collision detected")
    relative_path = registry_repo_relative_path or registry_path.name
    return ApplicationIdCollisionProof(
        registry_path=relative_path,
        application_id_registry_sha256=registry_sha256,
        research_attestation_sha256=research_sha256,
        parsed_application_id_count=len(application_ids),
    )


def _normalize_sql(value: str) -> str:
    return " ".join(value.split())


def _quoted_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _scalar(connection: sqlite3.Connection, statement: str) -> Any:
    row = connection.execute(statement).fetchone()
    if row is None:
        raise SQLiteManifestAuthorityError("SQLite PRAGMA returned no value")
    return row[0]


def _schema_objects(connection: sqlite3.Connection) -> tuple[SQLiteSchemaObject, ...]:
    rows = connection.execute(
        """
        SELECT type, name, tbl_name, sql
        FROM sqlite_schema
        WHERE name NOT LIKE 'sqlite\\_%' ESCAPE '\\'
        ORDER BY CASE type
            WHEN 'table' THEN 1
            WHEN 'index' THEN 2
            WHEN 'trigger' THEN 3
            WHEN 'view' THEN 4
            ELSE 5
        END, name
        """
    ).fetchall()
    objects: list[SQLiteSchemaObject] = []
    for object_type, name, table_name, sql in rows:
        if object_type not in {"table", "index", "trigger", "view"} or sql is None:
            raise SQLiteManifestAuthorityError("unexpected SQLite schema object")
        objects.append(
            SQLiteSchemaObject(
                object_type=cast(Literal["table", "index", "trigger", "view"], object_type),
                name=cast(str, name),
                table_name=cast(str, table_name),
                sql=_normalize_sql(cast(str, sql)),
            )
        )
    return tuple(objects)


def _table_columns(
    connection: sqlite3.Connection,
) -> dict[str, tuple[SQLiteColumn, ...]]:
    result: dict[str, tuple[SQLiteColumn, ...]] = {}
    for table in EXPECTED_TABLES:
        rows = connection.execute(f"PRAGMA table_info({_quoted_identifier(table)})").fetchall()
        result[table] = tuple(
            SQLiteColumn(
                cid=cast(int, row[0]),
                name=cast(str, row[1]),
                declared_type=cast(str, row[2]),
                not_null=cast(Literal[0, 1], row[3]),
                default_sql=cast(str | None, row[4]),
                primary_key_ordinal=cast(int, row[5]),
            )
            for row in rows
        )
    return result


def _foreign_keys(
    connection: sqlite3.Connection,
) -> dict[str, tuple[SQLiteForeignKey, ...]]:
    result: dict[str, tuple[SQLiteForeignKey, ...]] = {}
    for table in EXPECTED_TABLES:
        rows = connection.execute(
            f"PRAGMA foreign_key_list({_quoted_identifier(table)})"
        ).fetchall()
        result[table] = tuple(
            SQLiteForeignKey(
                foreign_key_id=cast(int, row[0]),
                sequence=cast(int, row[1]),
                referenced_table=cast(str, row[2]),
                from_column=cast(str, row[3]),
                to_column=cast(str, row[4]),
                on_update=cast(str, row[5]),
                on_delete=cast(str, row[6]),
                match=cast(str, row[7]),
            )
            for row in rows
        )
    return result


def _indexes(connection: sqlite3.Connection) -> dict[str, tuple[SQLiteIndex, ...]]:
    result: dict[str, tuple[SQLiteIndex, ...]] = {}
    for table in EXPECTED_TABLES:
        indexes: list[SQLiteIndex] = []
        rows = connection.execute(f"PRAGMA index_list({_quoted_identifier(table)})").fetchall()
        for row in sorted(rows, key=lambda value: cast(str, value[1])):
            name = cast(str, row[1])
            column_rows = connection.execute(
                f"PRAGMA index_xinfo({_quoted_identifier(name)})"
            ).fetchall()
            indexes.append(
                SQLiteIndex(
                    name=name,
                    unique=cast(Literal[0, 1], row[2]),
                    origin=cast(Literal["c", "u", "pk"], row[3]),
                    partial=cast(Literal[0, 1], row[4]),
                    columns=tuple(
                        SQLiteIndexColumn(
                            sequence=cast(int, column[0]),
                            column_id=cast(int, column[1]),
                            column_name=cast(str | None, column[2]),
                            descending=cast(Literal[0, 1], column[3]),
                            collation=cast(str | None, column[4]),
                            key_column=cast(Literal[0, 1], column[5]),
                        )
                        for column in column_rows
                    ),
                )
            )
        result[table] = tuple(indexes)
    return result


def _manifest_from_connection(
    connection: sqlite3.Connection,
    *,
    ddl_sha256: str,
    collision_proof: ApplicationIdCollisionProof,
) -> SQLiteLogicalSchemaManifest:
    application_id = cast(int, _scalar(connection, "PRAGMA application_id"))
    user_version = cast(int, _scalar(connection, "PRAGMA user_version"))
    if application_id != APPLICATION_ID or user_version != SQLITE_USER_VERSION:
        raise SQLiteManifestAuthorityError("SQLite authority header values do not match")
    return SQLiteLogicalSchemaManifest(
        ddl_sha256=ddl_sha256,
        required_pragmas={
            "foreign_keys": 1,
            "journal_mode": "delete",
            "trusted_schema": 0,
        },
        application_id_collision_proof=collision_proof,
        ordered_schema_objects=_schema_objects(connection),
        table_columns=_table_columns(connection),
        foreign_keys=_foreign_keys(connection),
        indexes=_indexes(connection),
    )


def _read_canonical_contract(path: Path, model: type[StrictContract]) -> StrictContract:
    payload, _ = _read_utf8_lf(path, label=path.name)
    try:
        value = json.loads(payload)
        contract = model.model_validate(value)
    except (json.JSONDecodeError, ValueError) as exc:
        raise SQLiteManifestAuthorityError(f"{path.name} contract is invalid") from exc
    if canonical_json_bytes(contract.model_dump(mode="json")) != payload:
        raise SQLiteManifestAuthorityError(f"{path.name} is not canonical JSON")
    return contract


def _write_exclusive(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except FileExistsError as exc:
        raise SQLiteManifestAuthorityError(f"{path.name} already exists") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _regular_file_bytes(path: Path, *, label: str) -> tuple[bytes, os.stat_result]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise SQLiteManifestAuthorityError(f"{label} could not be inspected") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise SQLiteManifestAuthorityError(f"{label} must be a regular non-symlink file")
    try:
        payload = path.read_bytes()
        after = path.lstat()
    except OSError as exc:
        raise SQLiteManifestAuthorityError(f"{label} could not be read") from exc
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    replay = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity != replay or before.st_size != len(payload):
        raise SQLiteManifestAuthorityError(f"{label} changed while being verified")
    return payload, after


def _sidecar_state(database_path: Path) -> dict[str, bool]:
    return {
        suffix.removeprefix("-"): (
            database_path.with_name(database_path.name + suffix).exists()
            or database_path.with_name(database_path.name + suffix).is_symlink()
        )
        for suffix in sorted(SIDECAR_SUFFIXES)
    }


def _require_no_sidecars(database_path: Path) -> dict[str, bool]:
    state = _sidecar_state(database_path)
    if any(state.values()):
        raise SQLiteManifestAuthorityError("SQLite sidecar exists")
    return state


def verify_sqlite_file_identity(
    *,
    repo_root: Path,
    database_path: Path,
    expected_identity: SQLiteRestrictedFileIdentity | None = None,
) -> SQLiteRestrictedFileIdentity:
    """Verify one exact restricted main file without following path aliases."""

    root = repo_root.resolve(strict=True)
    database = _absolute_inside_repository(root, database_path, label="SQLite database")
    try:
        relative = database.relative_to(root).as_posix()
    except ValueError as exc:  # pragma: no cover - bounded helper already rejects this
        raise SQLiteManifestAuthorityError("SQLite database escapes the repository") from exc
    if (
        re.fullmatch(
            r"artifacts/restricted/catalog/v2/sqlite/releases/"
            r"[0-9a-f]{64}/evaluation-authority\.sqlite3",
            relative,
        )
        is None
    ):
        raise SQLiteManifestAuthorityError("SQLite database path is not the exact restricted form")

    restricted_root = root / INITIALIZATION_RESTRICTED_ROOT
    releases = restricted_root / "releases"
    _require_private_directory(root, restricted_root, label="restricted SQLite root")
    _require_private_directory(root, releases, label="SQLite releases directory")
    _require_private_directory(root, database.parent, label="SQLite release directory")
    _require_no_sidecars(database)

    payload, observed = _read_regular_nofollow(
        database,
        label="restricted SQLite database",
        expected_mode=0o600,
        max_bytes=16 * 1024 * 1024,
    )
    if payload[:16] != b"SQLite format 3\x00":
        raise SQLiteManifestAuthorityError("restricted database has an invalid SQLite header")
    identity = SQLiteRestrictedFileIdentity(
        relative_path=relative,
        sha256=_sha256(payload),
        size_bytes=len(payload),
        device=observed.st_dev,
        inode=observed.st_ino,
        uid=observed.st_uid,
        mode="0600",
        link_count=cast(Literal[1], observed.st_nlink),
        no_follow_result="LSTAT_OPEN_FSTAT_MATCH",
    )
    if expected_identity is not None and identity != expected_identity:
        raise SQLiteManifestAuthorityError("restricted SQLite file identity drifted")
    return identity


@contextmanager
def _held_sqlite_path_guard(
    *, repo_root: Path, database_path: Path
) -> Iterator[SQLiteRestrictedFileIdentity]:
    """Retain cooperating directory/file guards across sqlite3 pathname opens."""

    expected = verify_sqlite_file_identity(
        repo_root=repo_root,
        database_path=database_path,
    )
    directory_descriptor = os.open(
        database_path.parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    file_descriptor = -1
    try:
        fcntl.flock(directory_descriptor, fcntl.LOCK_SH)
        file_descriptor = os.open(
            database_path.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory_descriptor,
        )
        opened = os.fstat(file_descriptor)
        if (opened.st_dev, opened.st_ino) != (expected.device, expected.inode):
            raise SQLiteManifestAuthorityError("SQLite guard opened a different main file")
        yield expected
        after = os.fstat(file_descriptor)
        path_after = database_path.lstat()
        if (after.st_dev, after.st_ino) != (expected.device, expected.inode) or (
            path_after.st_dev,
            path_after.st_ino,
        ) != (expected.device, expected.inode):
            raise SQLiteManifestAuthorityError("SQLite path identity changed across DB-API open")
        verify_sqlite_file_identity(
            repo_root=repo_root,
            database_path=database_path,
            expected_identity=expected,
        )
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)
        fcntl.flock(directory_descriptor, fcntl.LOCK_UN)
        os.close(directory_descriptor)


def _connect_read_only(database_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        f"{database_path.as_uri()}?mode=ro",
        uri=True,
        autocommit=True,
    )
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA trusted_schema=OFF")
    connection.execute("PRAGMA query_only=ON")
    return connection


def derive_logical_seal_sha256(
    *,
    logical_schema_sha256: str,
    seal: dict[str, object],
    ordered_members: Iterable[dict[str, object]],
    authority_request_sha256: str,
) -> str:
    """Derive the protected logical seal without publishing member material."""

    if re.fullmatch(r"[0-9a-f]{64}", logical_schema_sha256) is None:
        raise SQLiteManifestAuthorityError("logical schema digest is malformed")
    if re.fullmatch(r"[0-9a-f]{64}", authority_request_sha256) is None:
        raise SQLiteManifestAuthorityError("authority request digest is malformed")
    allowed_seal_keys = {
        "blind_count",
        "canonicalization_version",
        "catalog_sha256",
        "dev_count",
        "manifest_version",
        "membership_sha256",
        "sealed_at_utc",
        "split_sha256",
        "total_count",
    }
    if set(seal) != allowed_seal_keys:
        raise SQLiteManifestAuthorityError("logical seal metadata inventory is not exact")
    if (
        seal.get("dev_count") != 24
        or seal.get("blind_count") != 12
        or seal.get("total_count") != 36
    ):
        raise SQLiteManifestAuthorityError("logical seal counts are not exact")
    normalized = _normalize_ordered_members(ordered_members)
    return canonical_sha256(
        {
            "authority_request_sha256": authority_request_sha256,
            "logical_schema_sha256": logical_schema_sha256,
            "ordered_members": normalized,
            "seal": seal,
        }
    )


def _normalize_ordered_members(
    ordered_members: Iterable[dict[str, object]],
) -> list[dict[str, object]]:
    members = tuple(ordered_members)
    if len(members) != 36:
        raise SQLiteManifestAuthorityError("logical seal requires exactly 36 members")
    identifiers: set[str] = set()
    normalized: list[dict[str, object]] = []
    for ordinal, member in enumerate(members, start=1):
        if set(member) != {"canonical_place_id", "member_ordinal", "split"}:
            raise SQLiteManifestAuthorityError("logical member inventory is not exact")
        identifier = member.get("canonical_place_id")
        split = member.get("split")
        if not isinstance(identifier, str) or not 1 <= len(identifier) <= 128:
            raise SQLiteManifestAuthorityError("logical member identifier is malformed")
        if identifier in identifiers:
            raise SQLiteManifestAuthorityError("logical member identifier is duplicated")
        if member.get("member_ordinal") != ordinal:
            raise SQLiteManifestAuthorityError("logical member ordering is not exact")
        expected_split = "DEV" if ordinal <= 24 else "BLIND"
        if split != expected_split:
            raise SQLiteManifestAuthorityError("logical member split/order is not exact")
        identifiers.add(identifier)
        normalized.append(
            {
                "canonical_place_id": identifier,
                "member_ordinal": ordinal,
                "split": split,
            }
        )
    return normalized


def derive_logical_seal_input_sha256(
    *,
    logical_schema_sha256: str,
    catalog_revision_sha256: str,
    split_manifest_sha256: str,
    membership_sha256: str,
    ordered_members: Iterable[dict[str, object]],
) -> str:
    """Derive the private member-bearing input bound by a public aggregate hash."""

    for value, label in (
        (logical_schema_sha256, "logical schema"),
        (catalog_revision_sha256, "catalog revision"),
        (split_manifest_sha256, "split manifest"),
        (membership_sha256, "membership"),
    ):
        if re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise SQLiteManifestAuthorityError(f"{label} digest is malformed")
    normalized = _normalize_ordered_members(ordered_members)
    return canonical_sha256(
        {
            "catalog_revision_sha256": catalog_revision_sha256,
            "logical_schema_sha256": logical_schema_sha256,
            "manifest_version": SEAL_MANIFEST_VERSION,
            "membership_sha256": membership_sha256,
            "ordered_members": normalized,
            "split_manifest_sha256": split_manifest_sha256,
        }
    )


def classify_sqlite_seal_state(
    connection: sqlite3.Connection,
    *,
    manifest_version: str,
    expected_request_sha256: str,
    expected_nonce_sha256: str,
    expected_logical_seal_sha256: str,
) -> SQLiteSealState:
    """Classify the complete common relation before any branch-specific action."""

    for value, label in (
        (expected_request_sha256, "request"),
        (expected_nonce_sha256, "nonce"),
        (expected_logical_seal_sha256, "logical seal"),
    ):
        if re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise SQLiteManifestAuthorityError(f"expected {label} digest is malformed")
    counts = {
        table: cast(int, _scalar(connection, f"SELECT count(*) FROM {table}"))
        for table in (
            "authority_consumptions",
            "manifest_members",
            "manifest_seals",
        )
    }
    classification: SQLiteSealClassification
    relation_facts: dict[str, object] = {"counts": counts}
    if counts == SEAL_EMPTY_COUNTS:
        classification = SQLiteSealClassification.EXACT_UNSEALED
    elif counts == {
        "authority_consumptions": 1,
        "manifest_members": 36,
        "manifest_seals": 1,
    }:
        seal = connection.execute(
            """
            SELECT manifest_version, authority_request_sha256,
                   logical_seal_sha256, dev_count, blind_count, total_count
            FROM manifest_seals
            """
        ).fetchone()
        consumption = connection.execute(
            """
            SELECT manifest_version, request_sha256, nonce_sha256,
                   logical_seal_sha256
            FROM authority_consumptions
            """
        ).fetchone()
        member_summary = connection.execute(
            """
            SELECT count(*), count(DISTINCT canonical_place_id),
                   min(member_ordinal), max(member_ordinal),
                   sum(CASE WHEN split = 'DEV' THEN 1 ELSE 0 END),
                   sum(CASE WHEN split = 'BLIND' THEN 1 ELSE 0 END)
            FROM manifest_members
            WHERE manifest_version = ?
            """,
            (manifest_version,),
        ).fetchone()
        exact = (
            seal
            == (
                manifest_version,
                expected_request_sha256,
                expected_logical_seal_sha256,
                24,
                12,
                36,
            )
            and consumption
            == (
                manifest_version,
                expected_request_sha256,
                expected_nonce_sha256,
                expected_logical_seal_sha256,
            )
            and member_summary == (36, 36, 1, 36, 24, 12)
        )
        classification = (
            SQLiteSealClassification.EXACT_COMMITTED
            if exact
            else SQLiteSealClassification.CONFLICTING
        )
        relation_facts.update(
            {
                "exact_expected_relation": exact,
                "member_summary": list(member_summary or ()),
                "seal_matches_expected": seal
                == (
                    manifest_version,
                    expected_request_sha256,
                    expected_logical_seal_sha256,
                    24,
                    12,
                    36,
                ),
                "consumption_matches_expected": consumption
                == (
                    manifest_version,
                    expected_request_sha256,
                    expected_nonce_sha256,
                    expected_logical_seal_sha256,
                ),
            }
        )
    elif (
        counts["manifest_seals"] <= 1
        and counts["manifest_members"] <= 36
        and counts["authority_consumptions"] <= 1
    ):
        classification = SQLiteSealClassification.PARTIAL
    else:
        classification = SQLiteSealClassification.CONFLICTING

    relation_sha256 = canonical_sha256(
        {
            "classification": classification.value,
            "manifest_version": manifest_version,
            **relation_facts,
        }
    )
    return SQLiteSealState(
        classification=classification,
        manifest_version=manifest_version,
        expected_request_sha256=expected_request_sha256,
        expected_nonce_sha256=expected_nonce_sha256,
        expected_logical_seal_sha256=expected_logical_seal_sha256,
        counts=counts,
        relation_sha256=relation_sha256,
    )


def _proof_from_projection(
    database_path: Path,
    *,
    manifest: SQLiteLogicalSchemaManifest,
    manifest_bytes: bytes,
) -> SQLiteEmptyProof:
    _require_no_sidecars(database_path)
    database_bytes, _ = _regular_file_bytes(database_path, label="empty SQLite projection")
    if database_bytes[:16] != b"SQLite format 3\x00":
        raise SQLiteManifestAuthorityError("empty projection has invalid SQLite header")
    connection = _connect_read_only(database_path)
    try:
        replay = _manifest_from_connection(
            connection,
            ddl_sha256=manifest.ddl_sha256,
            collision_proof=manifest.application_id_collision_proof,
        )
        if replay != manifest:
            raise SQLiteManifestAuthorityError("logical schema does not match manifest")
        effective_pragmas: dict[str, int | str] = {
            "foreign_keys": cast(int, _scalar(connection, "PRAGMA foreign_keys")),
            "journal_mode": cast(str, _scalar(connection, "PRAGMA journal_mode")),
            "query_only": cast(int, _scalar(connection, "PRAGMA query_only")),
            "trusted_schema": cast(int, _scalar(connection, "PRAGMA trusted_schema")),
        }
        row_counts: dict[str, int] = {
            table: cast(
                int,
                _scalar(connection, f"SELECT count(*) FROM {_quoted_identifier(table)}"),
            )
            for table in EXPECTED_TABLES
        }
        freelist_count = cast(int, _scalar(connection, "PRAGMA freelist_count"))
        integrity_rows = connection.execute("PRAGMA integrity_check").fetchall()
        foreign_key_rows = connection.execute("PRAGMA foreign_key_check").fetchall()
        sqlite_sequence_present = (
            connection.execute(
                "SELECT 1 FROM sqlite_schema WHERE name = 'sqlite_sequence'"
            ).fetchone()
            is not None
        )
    finally:
        connection.close()
    replay_bytes, _ = _regular_file_bytes(
        database_path,
        label="empty SQLite projection",
    )
    if not hmac.compare_digest(_sha256(database_bytes), _sha256(replay_bytes)):
        raise SQLiteManifestAuthorityError(
            "empty SQLite projection changed during read-only replay"
        )
    sidecars = _require_no_sidecars(database_path)
    expected_names = {row.name for row in manifest.ordered_schema_objects}
    actual_names = {row.name for row in replay.ordered_schema_objects}
    unexpected = tuple(sorted(actual_names - expected_names))
    if any(row_counts.values()):
        raise SQLiteManifestAuthorityError("empty projection row count is non-zero")
    if freelist_count != 0:
        raise SQLiteManifestAuthorityError("empty projection freelist is non-zero")
    if integrity_rows != [("ok",)]:
        raise SQLiteManifestAuthorityError("empty projection integrity check failed")
    if foreign_key_rows:
        raise SQLiteManifestAuthorityError("empty projection foreign-key check failed")
    if sqlite_sequence_present or unexpected:
        raise SQLiteManifestAuthorityError("empty projection schema has unexpected objects")
    file_sha256 = _sha256(database_bytes)
    schema_object_sha256 = canonical_sha256(
        [row.model_dump(mode="json") for row in replay.ordered_schema_objects]
    )
    return SQLiteEmptyProof(
        ddl_sha256=manifest.ddl_sha256,
        logical_schema_manifest_sha256=_sha256(manifest_bytes),
        logical_schema_sha256=cast(str, manifest.logical_schema_sha256),
        application_id_collision_proof=manifest.application_id_collision_proof,
        sqlite_version=sqlite3.sqlite_version,
        effective_pragmas=effective_pragmas,
        empty_file_identity=SQLiteFileIdentity(
            sha256=file_sha256,
            size_bytes=len(database_bytes),
        ),
        empty_file_sha256=file_sha256,
        empty_file_size_bytes=len(database_bytes),
        schema_object_sha256=schema_object_sha256,
        row_counts=row_counts,
        freelist_count=cast(Literal[0], freelist_count),
        integrity_check="ok",
        foreign_key_check_count=cast(Literal[0], len(foreign_key_rows)),
        sqlite_sequence_present=sqlite_sequence_present,
        unexpected_schema_objects=unexpected,
        sidecars=sidecars,
    )


def _assert_private_values_absent(paths: Iterable[Path], values: Iterable[str]) -> None:
    forbidden = tuple(value.encode("utf-8") for value in values if value)
    if not forbidden:
        return
    for path in paths:
        payload = path.read_bytes()
        if any(value in payload for value in forbidden):
            raise SQLiteManifestAuthorityError("private membership material detected")


def verify_empty_projection(
    schema_dir: Path,
    *,
    research_path: Path = _DEFAULT_RESEARCH_PATH,
    as_of: date = APPLICATION_ID_RETRIEVED_ON,
    forbidden_values: Iterable[str] = (),
) -> SQLiteEmptyProof:
    """Verify the tracked projection without creating or mutating SQLite state."""

    schema_dir = schema_dir.resolve(strict=True)
    if not schema_dir.is_dir():
        raise SQLiteManifestAuthorityError("schema directory is not a directory")
    ddl_path = schema_dir / "schema.sql"
    registry_path = schema_dir / "sqlite-application-ids-2026-08-02.txt"
    manifest_path = schema_dir / "logical-schema-manifest.json"
    database_path = schema_dir / "empty.sqlite3"
    proof_path = schema_dir / "empty-proof.json"
    _require_no_sidecars(database_path)
    ddl_bytes, _ = _read_utf8_lf(ddl_path, label="schema DDL")
    collision_proof = verify_application_id_collision(
        registry_path,
        research_path=research_path,
        as_of=as_of,
        registry_repo_relative_path=REGISTRY_RELPATH,
    )
    manifest = cast(
        SQLiteLogicalSchemaManifest,
        _read_canonical_contract(manifest_path, SQLiteLogicalSchemaManifest),
    )
    proof = cast(
        SQLiteEmptyProof,
        _read_canonical_contract(proof_path, SQLiteEmptyProof),
    )
    manifest_bytes = manifest_path.read_bytes()
    if not hmac.compare_digest(manifest.ddl_sha256, _sha256(ddl_bytes)):
        raise SQLiteManifestAuthorityError("schema DDL digest drift")
    if manifest.application_id_collision_proof != collision_proof:
        raise SQLiteManifestAuthorityError("application-id collision proof drift")
    derived = _proof_from_projection(
        database_path,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
    )
    if derived != proof:
        if derived.empty_file_sha256 != proof.empty_file_sha256:
            raise SQLiteManifestAuthorityError("empty projection file digest drift")
        raise SQLiteManifestAuthorityError("empty projection proof drift")
    _assert_private_values_absent(
        (ddl_path, manifest_path, database_path, proof_path),
        forbidden_values,
    )
    return derived


def _ddl_statements(ddl: str) -> tuple[str, ...]:
    statements: list[str] = []
    buffer = ""
    for line in ddl.splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            statement = buffer.strip()
            if statement:
                statements.append(statement)
            buffer = ""
    if buffer.strip():
        raise SQLiteManifestAuthorityError("schema DDL ends with incomplete statement")
    return tuple(statements)


def build_tracked_empty_projection(
    schema_dir: Path,
    *,
    research_path: Path,
    as_of: date,
) -> tuple[SQLiteLogicalSchemaManifest, SQLiteEmptyProof]:
    """Build a new schema-only SQLite projection without replacing any artifact."""

    schema_dir = schema_dir.resolve(strict=True)
    if not schema_dir.is_dir():
        raise SQLiteManifestAuthorityError("schema directory is not a directory")
    ddl_path = schema_dir / "schema.sql"
    registry_path = schema_dir / "sqlite-application-ids-2026-08-02.txt"
    database_path = schema_dir / "empty.sqlite3"
    manifest_path = schema_dir / "logical-schema-manifest.json"
    proof_path = schema_dir / "empty-proof.json"
    for output in (database_path, manifest_path, proof_path):
        if output.exists() or output.is_symlink():
            raise SQLiteManifestAuthorityError(f"{output.name} already exists")
    collision_proof = verify_application_id_collision(
        registry_path,
        research_path=research_path,
        as_of=as_of,
        registry_repo_relative_path=REGISTRY_RELPATH,
    )
    ddl_bytes, ddl = _read_utf8_lf(ddl_path, label="schema DDL")
    statements = _ddl_statements(ddl)
    staging = schema_dir / f".empty.sqlite3.{secrets.token_hex(12)}.staging"
    descriptor = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    try:
        connection = sqlite3.connect(staging, autocommit=True)
        try:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version={SQLITE_USER_VERSION}")
            connection.execute("BEGIN IMMEDIATE")
            try:
                for statement in statements:
                    connection.execute(statement)
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            manifest = _manifest_from_connection(
                connection,
                ddl_sha256=_sha256(ddl_bytes),
                collision_proof=collision_proof,
            )
        finally:
            connection.close()
        _require_no_sidecars(staging)
        try:
            os.link(staging, database_path)
        except FileExistsError as exc:
            raise SQLiteManifestAuthorityError("empty.sqlite3 already exists") from exc
        staging.unlink()
        manifest_bytes = canonical_json_bytes(manifest.model_dump(mode="json"))
        _write_exclusive(manifest_path, manifest_bytes)
        proof = _proof_from_projection(
            database_path,
            manifest=manifest,
            manifest_bytes=manifest_bytes,
        )
        _write_exclusive(
            proof_path,
            canonical_json_bytes(proof.model_dump(mode="json")),
        )
        verified = verify_empty_projection(
            schema_dir,
            research_path=research_path,
            as_of=as_of,
        )
        return manifest, verified
    except BaseException:
        if staging.exists() and staging.is_file():
            staging.unlink()
        raise


def _absolute_inside_repository(repo_root: Path, path: Path, *, label: str) -> Path:
    root = repo_root.resolve(strict=True)
    candidate = Path(os.path.abspath(path if path.is_absolute() else root / path))
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise SQLiteManifestAuthorityError(f"{label} escapes the repository") from exc
    if not relative.parts or ".." in relative.parts:
        raise SQLiteManifestAuthorityError(f"{label} is not a bounded repository path")
    return candidate


def _walk_directory_nofollow(
    repo_root: Path,
    directory: Path,
    *,
    label: str,
) -> os.stat_result:
    root = repo_root.resolve(strict=True)
    candidate = _absolute_inside_repository(root, directory, label=label)
    relative = candidate.relative_to(root)
    current = root
    expected_uid = os.getuid()
    last = root.lstat()
    for part in relative.parts:
        current = current / part
        try:
            before = current.lstat()
        except OSError as exc:
            raise SQLiteManifestAuthorityError(f"{label} ancestor is absent") from exc
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
            raise SQLiteManifestAuthorityError(f"{label} contains a symlink or non-directory")
        if before.st_uid != expected_uid:
            raise SQLiteManifestAuthorityError(f"{label} has the wrong owner")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = os.open(current, flags)
        try:
            opened = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after = current.lstat()
        identity = (before.st_dev, before.st_ino, before.st_mode, before.st_uid)
        if identity != (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid):
            raise SQLiteManifestAuthorityError(f"{label} identity changed during open")
        if identity != (after.st_dev, after.st_ino, after.st_mode, after.st_uid):
            raise SQLiteManifestAuthorityError(f"{label} identity changed after open")
        last = after
    return last


def _require_private_directory(
    repo_root: Path,
    directory: Path,
    *,
    label: str,
) -> os.stat_result:
    result = _walk_directory_nofollow(repo_root, directory, label=label)
    if stat.S_IMODE(result.st_mode) != 0o700:
        raise SQLiteManifestAuthorityError(f"{label} mode must be 0700")
    return result


def _ensure_restricted_root(repo_root: Path, restricted_root: Path) -> None:
    expected = repo_root.resolve(strict=True) / INITIALIZATION_RESTRICTED_ROOT
    candidate = _absolute_inside_repository(
        repo_root,
        restricted_root,
        label="restricted SQLite root",
    )
    if candidate != expected:
        raise SQLiteManifestAuthorityError("restricted SQLite root is not the exact allowlist")
    parent = candidate.parent
    _walk_directory_nofollow(repo_root, parent, label="restricted SQLite root parent")
    if not candidate.exists() and not candidate.is_symlink():
        os.mkdir(candidate, 0o700)
    _require_private_directory(repo_root, candidate, label="restricted SQLite root")


def _read_regular_nofollow(
    path: Path,
    *,
    label: str,
    expected_mode: int | None = None,
    expected_uid: int | None = None,
    require_single_link: bool = True,
    max_bytes: int = 8 * 1024 * 1024,
) -> tuple[bytes, os.stat_result]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise SQLiteManifestAuthorityError(f"{label} could not be inspected") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise SQLiteManifestAuthorityError(f"{label} must be a regular non-symlink file")
    if expected_mode is not None and stat.S_IMODE(before.st_mode) != expected_mode:
        raise SQLiteManifestAuthorityError(f"{label} mode is not {expected_mode:04o}")
    owner = os.getuid() if expected_uid is None else expected_uid
    if before.st_uid != owner:
        raise SQLiteManifestAuthorityError(f"{label} has the wrong owner")
    if require_single_link and before.st_nlink != 1:
        raise SQLiteManifestAuthorityError(f"{label} link count is not one")
    if before.st_size > max_bytes:
        raise SQLiteManifestAuthorityError(f"{label} exceeds the bounded size")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after_open = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after_path = path.lstat()
    identity = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
    )
    if identity != (
        opened.st_dev,
        opened.st_ino,
        opened.st_mode,
        opened.st_uid,
        opened.st_nlink,
        opened.st_size,
        opened.st_mtime_ns,
    ):
        raise SQLiteManifestAuthorityError(f"{label} identity changed during no-follow open")
    if identity != (
        after_open.st_dev,
        after_open.st_ino,
        after_open.st_mode,
        after_open.st_uid,
        after_open.st_nlink,
        after_open.st_size,
        after_open.st_mtime_ns,
    ) or identity != (
        after_path.st_dev,
        after_path.st_ino,
        after_path.st_mode,
        after_path.st_uid,
        after_path.st_nlink,
        after_path.st_size,
        after_path.st_mtime_ns,
    ):
        raise SQLiteManifestAuthorityError(f"{label} identity changed while being read")
    if len(payload) != before.st_size or len(payload) > max_bytes:
        raise SQLiteManifestAuthorityError(f"{label} bounded read is incomplete")
    return payload, after_path


def _load_canonical_nofollow(
    path: Path,
    model: type[StrictContract],
    *,
    label: str,
    expected_mode: int,
) -> StrictContract:
    payload, _ = _read_regular_nofollow(
        path,
        label=label,
        expected_mode=expected_mode,
        max_bytes=2 * 1024 * 1024,
    )
    try:
        contract = model.model_validate(json.loads(payload))
    except (json.JSONDecodeError, ValueError) as exc:
        raise SQLiteManifestAuthorityError(f"{label} contract is invalid") from exc
    if canonical_json_bytes(contract.model_dump(mode="json")) != payload:
        raise SQLiteManifestAuthorityError(f"{label} is not canonical JSON")
    return contract


def _contains_forbidden_structure(value: object) -> bool:
    forbidden_keys = {
        "blind_members",
        "canonical_place_id",
        "complement",
        "dev_members",
        "member_ids",
        "member_order",
        "members",
        "ordered_members",
        "per_member",
        "per_member_digests",
    }
    if isinstance(value, dict):
        if any(str(key).lower() in forbidden_keys for key in value):
            return True
        return any(_contains_forbidden_structure(child) for child in value.values())
    if isinstance(value, list):
        return any(_contains_forbidden_structure(child) for child in value)
    if isinstance(value, str):
        return value.startswith("itda-auth-v2:") or value.startswith("file:")
    return False


def _assert_sanitized_surface(value: object, *, label: str) -> None:
    if _contains_forbidden_structure(value):
        raise SQLiteManifestAuthorityError(
            f"{label} contains forbidden membership or capability data"
        )
    payload = canonical_json_bytes(value)
    if b"itda-auth-v2:" in payload or b'"nonce"' in payload:
        raise SQLiteManifestAuthorityError(f"{label} contains raw authority material")


def _split_approval_facts(path: Path) -> tuple[str, str]:
    payload, _ = _read_regular_nofollow(
        path,
        label="split approval",
        expected_mode=0o600,
        max_bytes=2 * 1024 * 1024,
    )
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise SQLiteManifestAuthorityError("split approval is not valid JSON") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != payload:
        raise SQLiteManifestAuthorityError("split approval is not canonical JSON")
    if _contains_forbidden_structure(value):
        raise SQLiteManifestAuthorityError("split approval contains direct membership")
    if value.get("schema_version") != "itda.real-split-approval.v2":
        raise SQLiteManifestAuthorityError("split approval schema is not exact")
    if value.get("status") != "APPROVED_UNSEALED" or value.get("seal_sha256") is not None:
        raise SQLiteManifestAuthorityError("split approval is not approved and unsealed")
    approval_sha256 = value.get("approval_sha256")
    if not isinstance(approval_sha256, str):
        raise SQLiteManifestAuthorityError("split approval lacks its canonical digest")
    expected = canonical_sha256(
        {key: item for key, item in value.items() if key != "approval_sha256"}
    )
    if not hmac.compare_digest(approval_sha256, expected):
        raise SQLiteManifestAuthorityError("split approval digest is stale")
    return _sha256(payload), approval_sha256


def _schema_initialization_facts(
    schema_dir: Path,
) -> tuple[
    SQLiteLogicalSchemaManifest,
    SQLiteEmptyProof,
    str,
    str,
]:
    proof = verify_empty_projection(schema_dir, as_of=APPLICATION_ID_RETRIEVED_ON)
    manifest_path = schema_dir.resolve(strict=True) / "logical-schema-manifest.json"
    proof_path = schema_dir.resolve(strict=True) / "empty-proof.json"
    manifest = cast(
        SQLiteLogicalSchemaManifest,
        _read_canonical_contract(manifest_path, SQLiteLogicalSchemaManifest),
    )
    manifest_bytes, _ = _read_regular_nofollow(
        manifest_path,
        label="logical schema manifest",
        expected_mode=None,
    )
    proof_bytes, _ = _read_regular_nofollow(
        proof_path,
        label="tracked empty proof",
        expected_mode=None,
    )
    if manifest.logical_schema_sha256 != proof.logical_schema_sha256:
        raise SQLiteManifestAuthorityError("logical schema and empty proof disagree")
    return manifest, proof, _sha256(manifest_bytes), _sha256(proof_bytes)


def _state_from_live(
    *,
    split_approval_path: Path,
    manifest: SQLiteLogicalSchemaManifest,
    proof: SQLiteEmptyProof,
    manifest_sha256: str,
    proof_sha256: str,
    prepared_at: datetime,
) -> SQLiteInitializationState:
    split_file_sha256, split_receipt_sha256 = _split_approval_facts(split_approval_path)
    return SQLiteInitializationState(
        split_approval_sha256=split_file_sha256,
        split_approval_receipt_sha256=split_receipt_sha256,
        ddl_sha256=manifest.ddl_sha256,
        logical_schema_manifest_sha256=manifest_sha256,
        logical_schema_sha256=cast(str, manifest.logical_schema_sha256),
        empty_proof_sha256=proof_sha256,
        tracked_empty_file_sha256=proof.empty_file_sha256,
        empty_counts=dict(INITIALIZATION_EMPTY_COUNTS),
        prepared_at=prepared_at,
    )


def _initialization_target(state: SQLiteInitializationState) -> dict[str, object]:
    return {
        "schema_version": "itda.sqlite-initialization-target.v1",
        "action": state.action,
        "restricted_root": state.restricted_root,
        "database_filename_sha256": _sha256(INITIALIZATION_DATABASE_NAME.encode("ascii")),
        "directory_mode": state.directory_mode,
        "database_mode": state.database_mode,
        "ddl_sha256": state.ddl_sha256,
        "logical_schema_sha256": state.logical_schema_sha256,
        "empty_counts": state.empty_counts,
        "membership_present": False,
    }


def _initialization_binding(
    state: SQLiteInitializationState,
    *,
    target_sha256: str,
) -> dict[str, object]:
    return {
        "schema_version": "itda.sqlite-initialization-binding.v1",
        "action": state.action,
        "state_attestation_sha256": state.state_attestation_sha256,
        "target_sha256": target_sha256,
        "split_approval_sha256": state.split_approval_sha256,
        "ddl_sha256": state.ddl_sha256,
        "logical_schema_sha256": state.logical_schema_sha256,
        "restricted_root": state.restricted_root,
    }


def _request_from_state(
    state: SQLiteInitializationState,
    *,
    target_sha256: str,
    binding_sha256: str,
    issued_at: datetime,
    expires_at: datetime,
) -> SQLiteInitializationRequest:
    return SQLiteInitializationRequest(
        state_attestation_sha256=cast(str, state.state_attestation_sha256),
        target_sha256=target_sha256,
        binding_sha256=binding_sha256,
        ddl_sha256=state.ddl_sha256,
        logical_schema_manifest_sha256=state.logical_schema_manifest_sha256,
        logical_schema_sha256=state.logical_schema_sha256,
        empty_proof_sha256=state.empty_proof_sha256,
        database_filename_sha256=_sha256(INITIALIZATION_DATABASE_NAME.encode("ascii")),
        empty_counts=dict(INITIALIZATION_EMPTY_COUNTS),
        issued_at=issued_at,
        expires_at=expires_at,
    )


def _write_canonical_exclusive(path: Path, value: StrictContract, *, mode: int) -> None:
    _write_exclusive(path, canonical_json_bytes(value.model_dump(mode="json")), mode=mode)
    os.chmod(path, mode)


def build_initialization_authority(
    *,
    repo_root: Path,
    schema_dir: Path,
    split_approval_path: Path,
    restricted_root: Path,
    state_output: Path,
    issuance_output: Path,
    request_output: Path,
    reviewer_id: str,
    nonce: str,
    issued_at: datetime,
    expires_at: datetime,
) -> tuple[
    SQLiteInitializationState,
    SQLiteInitializationRequest,
    AuthorityIssuanceContext,
]:
    """Prepare one exact membership-free request without creating its real target."""

    root = repo_root.resolve(strict=True)
    canonical_issued_at = require_utc(issued_at, field_name="issued_at")
    canonical_expires_at = require_utc(expires_at, field_name="expires_at")
    if re.fullmatch(r"[0-9a-f]{64}", nonce) is None:
        raise SQLiteManifestAuthorityError("initialization nonce is not canonical SHA-256 text")
    _ensure_restricted_root(root, restricted_root)
    exact_state = restricted_root / "initialization-state-attestation.json"
    exact_issuance = restricted_root / "initialization-issuance-context.json"
    exact_request = root / "artifacts/public/catalog/v2/sqlite-initialization-request.json"
    if (
        state_output != exact_state
        or issuance_output != exact_issuance
        or request_output != exact_request
    ):
        raise SQLiteManifestAuthorityError("initialization output path is not exact")
    if (restricted_root / "releases").exists() or (restricted_root / "releases").is_symlink():
        raise SQLiteManifestAuthorityError("real restricted release target already exists")
    for output in (state_output, issuance_output, request_output):
        if output.exists() or output.is_symlink():
            raise SQLiteManifestAuthorityError(f"{output.name} already exists")

    manifest, proof, manifest_sha256, proof_sha256 = _schema_initialization_facts(schema_dir)
    state = _state_from_live(
        split_approval_path=split_approval_path,
        manifest=manifest,
        proof=proof,
        manifest_sha256=manifest_sha256,
        proof_sha256=proof_sha256,
        prepared_at=canonical_issued_at,
    )
    target = _initialization_target(state)
    target_sha256 = canonical_sha256(target)
    binding = _initialization_binding(state, target_sha256=target_sha256)
    binding_sha256 = canonical_sha256(binding)
    request = _request_from_state(
        state,
        target_sha256=target_sha256,
        binding_sha256=binding_sha256,
        issued_at=canonical_issued_at,
        expires_at=canonical_expires_at,
    )
    issuance = freeze_issuance_context(
        action=INITIALIZATION_ACTION,
        request=request.model_dump(exclude={"request_sha256"}, mode="json"),
        state_attestation=state.model_dump(exclude={"state_attestation_sha256"}, mode="json"),
        target=target,
        reviewer_id=reviewer_id,
        binding=binding,
        nonce=nonce,
        issued_at=canonical_issued_at,
        expires_at=canonical_expires_at,
        reviewer_channel_risk=(
            "Reviewer identity is accepted local-channel metadata, not a "
            "cryptographic identity claim."
        ),
    )
    if request.request_sha256 != issuance.request_sha256:
        raise SQLiteManifestAuthorityError("request and issuance context disagree")
    _assert_sanitized_surface(state.model_dump(mode="json"), label="initialization state")
    _assert_sanitized_surface(request.model_dump(mode="json"), label="initialization request")

    request_output.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    created: list[Path] = []
    try:
        _write_canonical_exclusive(state_output, state, mode=0o600)
        created.append(state_output)
        _write_canonical_exclusive(issuance_output, issuance, mode=0o600)
        created.append(issuance_output)
        _write_canonical_exclusive(request_output, request, mode=0o644)
        created.append(request_output)
    except BaseException:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        raise
    return state, request, issuance


def _load_initialization_inputs(
    *,
    repo_root: Path,
    schema_dir: Path,
    state_path: Path,
    issuance_context_path: Path,
    request_path: Path,
    require_target_absent: bool,
) -> tuple[
    SQLiteInitializationState,
    SQLiteInitializationRequest,
    AuthorityIssuanceContext,
    dict[str, object],
    dict[str, object],
    Path,
]:
    root = repo_root.resolve(strict=True)
    restricted_root = root / INITIALIZATION_RESTRICTED_ROOT
    _require_private_directory(root, restricted_root, label="restricted SQLite root")
    if state_path != restricted_root / "initialization-state-attestation.json":
        raise SQLiteManifestAuthorityError("initialization state path is not exact")
    if issuance_context_path != restricted_root / "initialization-issuance-context.json":
        raise SQLiteManifestAuthorityError("initialization issuance path is not exact")
    if request_path != root / "artifacts/public/catalog/v2/sqlite-initialization-request.json":
        raise SQLiteManifestAuthorityError("initialization request path is not exact")
    state = cast(
        SQLiteInitializationState,
        _load_canonical_nofollow(
            state_path,
            SQLiteInitializationState,
            label="initialization state",
            expected_mode=0o600,
        ),
    )
    issuance = cast(
        AuthorityIssuanceContext,
        _load_canonical_nofollow(
            issuance_context_path,
            AuthorityIssuanceContext,
            label="initialization issuance context",
            expected_mode=0o600,
        ),
    )
    request = cast(
        SQLiteInitializationRequest,
        _load_canonical_nofollow(
            request_path,
            SQLiteInitializationRequest,
            label="initialization request",
            expected_mode=0o644,
        ),
    )
    manifest, proof, manifest_sha256, proof_sha256 = _schema_initialization_facts(schema_dir)
    split_approval_path = root / state.split_approval_path
    expected_state = _state_from_live(
        split_approval_path=split_approval_path,
        manifest=manifest,
        proof=proof,
        manifest_sha256=manifest_sha256,
        proof_sha256=proof_sha256,
        prepared_at=state.prepared_at,
    )
    if state != expected_state:
        raise SQLiteManifestAuthorityError("initialization state drifted from live parents")
    target = _initialization_target(state)
    target_sha256 = canonical_sha256(target)
    binding = _initialization_binding(state, target_sha256=target_sha256)
    expected_request = _request_from_state(
        state,
        target_sha256=target_sha256,
        binding_sha256=canonical_sha256(binding),
        issued_at=issuance.issued_at,
        expires_at=issuance.expires_at,
    )
    if request != expected_request:
        raise SQLiteManifestAuthorityError("initialization request drifted from live parents")
    expected_issuance = freeze_issuance_context(
        action=INITIALIZATION_ACTION,
        request=request.model_dump(exclude={"request_sha256"}, mode="json"),
        state_attestation=state.model_dump(exclude={"state_attestation_sha256"}, mode="json"),
        target=target,
        reviewer_id=issuance.reviewer_id,
        binding=binding,
        nonce=issuance.nonce,
        issued_at=issuance.issued_at,
        expires_at=issuance.expires_at,
        reviewer_channel_risk=issuance.reviewer_channel_risk,
    )
    if issuance != expected_issuance:
        raise SQLiteManifestAuthorityError("initialization issuance context drifted")
    _assert_sanitized_surface(state.model_dump(mode="json"), label="initialization state")
    _assert_sanitized_surface(request.model_dump(mode="json"), label="initialization request")
    target_path = restricted_root / "releases" / target_sha256 / INITIALIZATION_DATABASE_NAME
    if require_target_absent:
        releases = restricted_root / "releases"
        receipt = restricted_root / "initialization-receipt.json"
        if releases.exists() or releases.is_symlink() or receipt.exists() or receipt.is_symlink():
            raise SQLiteManifestAuthorityError("initialization target or receipt already exists")
    return state, request, issuance, target, binding, target_path


def check_initialization_request(
    *,
    repo_root: Path,
    schema_dir: Path,
    state_path: Path,
    issuance_context_path: Path,
    request_path: Path,
) -> SQLiteInitializationRequest:
    """Independently rederive a request while its real target remains absent."""

    _, request, _, _, _, _ = _load_initialization_inputs(
        repo_root=repo_root,
        schema_dir=schema_dir,
        state_path=state_path,
        issuance_context_path=issuance_context_path,
        request_path=request_path,
        require_target_absent=True,
    )
    return request


def _restricted_empty_facts(
    *,
    repo_root: Path,
    schema_dir: Path,
    database_path: Path,
) -> dict[str, object]:
    root = repo_root.resolve(strict=True)
    _require_private_directory(root, database_path.parent, label="SQLite release directory")
    _require_no_sidecars(database_path)
    before_bytes, before = _read_regular_nofollow(
        database_path,
        label="restricted empty database",
        expected_mode=0o600,
        max_bytes=16 * 1024 * 1024,
    )
    if before_bytes[:16] != b"SQLite format 3\x00":
        raise SQLiteManifestAuthorityError("restricted database has an invalid SQLite header")
    manifest, _, _, _ = _schema_initialization_facts(schema_dir)
    connection = _connect_read_only(database_path)
    try:
        replay = _manifest_from_connection(
            connection,
            ddl_sha256=manifest.ddl_sha256,
            collision_proof=manifest.application_id_collision_proof,
        )
        if replay != manifest:
            raise SQLiteManifestAuthorityError("restricted database logical schema drifted")
        effective_pragmas: dict[str, int | str] = {
            "foreign_keys": cast(int, _scalar(connection, "PRAGMA foreign_keys")),
            "journal_mode": cast(str, _scalar(connection, "PRAGMA journal_mode")),
            "query_only": cast(int, _scalar(connection, "PRAGMA query_only")),
            "trusted_schema": cast(int, _scalar(connection, "PRAGMA trusted_schema")),
        }
        all_counts = {
            table: cast(
                int,
                _scalar(connection, f"SELECT count(*) FROM {_quoted_identifier(table)}"),
            )
            for table in EXPECTED_TABLES
        }
        freelist_count = cast(int, _scalar(connection, "PRAGMA freelist_count"))
        integrity_rows = connection.execute("PRAGMA integrity_check").fetchall()
        foreign_key_rows = connection.execute("PRAGMA foreign_key_check").fetchall()
    finally:
        connection.close()
    after_bytes, after = _read_regular_nofollow(
        database_path,
        label="restricted empty database",
        expected_mode=0o600,
        max_bytes=16 * 1024 * 1024,
    )
    if any(all_counts.values()) or freelist_count != 0:
        raise SQLiteManifestAuthorityError("restricted database is not exactly empty")
    if integrity_rows != [("ok",)] or foreign_key_rows:
        raise SQLiteManifestAuthorityError("restricted database integrity check failed")
    if _sha256(before_bytes) != _sha256(after_bytes):
        raise SQLiteManifestAuthorityError("restricted database changed during read-only replay")
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise SQLiteManifestAuthorityError("restricted database identity changed during replay")
    sidecars = _require_no_sidecars(database_path)
    relative_path = database_path.relative_to(root).as_posix()
    return {
        "effective_pragmas": effective_pragmas,
        "empty_counts": {
            "authority_consumptions": all_counts["authority_consumptions"],
            "manifest_members": all_counts["manifest_members"],
            "manifest_seals": all_counts["manifest_seals"],
        },
        "freelist_count": freelist_count,
        "integrity_check": "ok",
        "foreign_key_check_count": len(foreign_key_rows),
        "sidecars": sidecars,
        "file_identity": SQLiteRestrictedFileIdentity(
            relative_path=relative_path,
            sha256=_sha256(after_bytes),
            size_bytes=len(after_bytes),
            device=after.st_dev,
            inode=after.st_ino,
            uid=after.st_uid,
            mode="0600",
            link_count=cast(Literal[1], after.st_nlink),
            no_follow_result="LSTAT_OPEN_FSTAT_MATCH",
        ),
    }


def initialize_restricted_empty_database(
    *,
    raw_token: str,
    repo_root: Path,
    schema_dir: Path,
    state_path: Path,
    issuance_context_path: Path,
    request_path: Path,
    receipt_output: Path,
    initialized_at: datetime,
) -> SQLiteInitializationReceipt:
    """Consume one exact authority by creating one schema-only restricted DB."""

    root = repo_root.resolve(strict=True)
    canonical_initialized_at = require_utc(initialized_at, field_name="initialized_at")
    state, request, issuance, target, binding, database_path = _load_initialization_inputs(
        repo_root=root,
        schema_dir=schema_dir,
        state_path=state_path,
        issuance_context_path=issuance_context_path,
        request_path=request_path,
        require_target_absent=True,
    )
    exact_receipt = root / INITIALIZATION_RESTRICTED_ROOT / "initialization-receipt.json"
    if receipt_output != exact_receipt:
        raise SQLiteManifestAuthorityError("initialization receipt path is not exact")
    validated = validate_authority_token(
        raw_token,
        issuance_context=issuance,
        request=request.model_dump(exclude={"request_sha256"}, mode="json"),
        state_attestation=state.model_dump(exclude={"state_attestation_sha256"}, mode="json"),
        target=target,
        binding=binding,
        reviewer_id=issuance.reviewer_id,
        now=canonical_initialized_at,
        revocation_tombstones=(),
    )

    restricted_root = root / INITIALIZATION_RESTRICTED_ROOT
    releases = restricted_root / "releases"
    os.mkdir(releases, 0o700)
    _require_private_directory(root, releases, label="SQLite releases directory")
    release = database_path.parent
    os.mkdir(release, 0o700)
    _require_private_directory(root, release, label="SQLite release directory")
    for suffix in SIDECAR_SUFFIXES:
        sidecar = database_path.with_name(database_path.name + suffix)
        if sidecar.exists() or sidecar.is_symlink():
            raise SQLiteManifestAuthorityError("SQLite sidecar already exists")

    directory_descriptor = os.open(
        release,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    file_descriptor = -1
    try:
        file_descriptor = os.open(
            INITIALIZATION_DATABASE_NAME,
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=directory_descriptor,
        )
        os.fchmod(file_descriptor, 0o600)
        guard_before = os.fstat(file_descriptor)
        ddl_bytes, ddl = _read_utf8_lf(
            schema_dir.resolve(strict=True) / "schema.sql",
            label="schema DDL",
        )
        if _sha256(ddl_bytes) != state.ddl_sha256:
            raise SQLiteManifestAuthorityError("schema DDL drifted before initialization")
        connection = sqlite3.connect(database_path, autocommit=True)
        try:
            journal_mode = cast(str, _scalar(connection, "PRAGMA journal_mode=DELETE"))
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            if journal_mode.lower() != "delete":
                raise SQLiteManifestAuthorityError("restricted database is not DELETE mode")
            if _scalar(connection, "PRAGMA foreign_keys") != 1:
                raise SQLiteManifestAuthorityError("restricted database foreign keys are disabled")
            if _scalar(connection, "PRAGMA trusted_schema") != 0:
                raise SQLiteManifestAuthorityError("restricted database trusted schema is enabled")
            connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version={SQLITE_USER_VERSION}")
            connection.execute("BEGIN IMMEDIATE")
            try:
                for statement in _ddl_statements(ddl):
                    connection.execute(statement)
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        finally:
            connection.close()
        os.fsync(file_descriptor)
        guard_after = os.fstat(file_descriptor)
        path_after = database_path.lstat()
        if (guard_before.st_dev, guard_before.st_ino) != (
            guard_after.st_dev,
            guard_after.st_ino,
        ) or (guard_after.st_dev, guard_after.st_ino) != (
            path_after.st_dev,
            path_after.st_ino,
        ):
            raise SQLiteManifestAuthorityError("restricted database path identity changed")
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)
        os.close(directory_descriptor)

    facts = _restricted_empty_facts(
        repo_root=root,
        schema_dir=schema_dir,
        database_path=database_path,
    )
    if issuance.context_sha256 is None or request.request_sha256 is None:
        raise SQLiteManifestAuthorityError("initialization authority lacks a digest")
    receipt = SQLiteInitializationReceipt(
        request_sha256=request.request_sha256,
        state_attestation_sha256=cast(str, state.state_attestation_sha256),
        target_sha256=request.target_sha256,
        binding_sha256=request.binding_sha256,
        token_sha256=validated.token_sha256,
        nonce_sha256=_sha256(issuance.nonce.encode("ascii")),
        issuance_context_sha256=issuance.context_sha256,
        ddl_sha256=state.ddl_sha256,
        logical_schema_manifest_sha256=state.logical_schema_manifest_sha256,
        logical_schema_sha256=state.logical_schema_sha256,
        empty_proof_sha256=state.empty_proof_sha256,
        sqlite_version=sqlite3.sqlite_version,
        effective_pragmas=cast(dict[str, int | str], facts["effective_pragmas"]),
        empty_counts=cast(dict[str, int], facts["empty_counts"]),
        freelist_count=cast(Literal[0], facts["freelist_count"]),
        integrity_check="ok",
        foreign_key_check_count=cast(Literal[0], facts["foreign_key_check_count"]),
        sidecars=cast(dict[str, bool], facts["sidecars"]),
        file_identity=cast(SQLiteRestrictedFileIdentity, facts["file_identity"]),
        initialized_at=canonical_initialized_at,
    )
    _assert_sanitized_surface(receipt.model_dump(mode="json"), label="initialization receipt")
    _write_canonical_exclusive(receipt_output, receipt, mode=0o600)
    return receipt


def verify_initialization_receipt(
    *,
    repo_root: Path,
    schema_dir: Path,
    state_path: Path,
    issuance_context_path: Path,
    request_path: Path,
    receipt_path: Path,
) -> SQLiteInitializationReceipt:
    """Reopen and independently verify the exact empty file and receipt."""

    root = repo_root.resolve(strict=True)
    state, request, issuance, _, _, database_path = _load_initialization_inputs(
        repo_root=root,
        schema_dir=schema_dir,
        state_path=state_path,
        issuance_context_path=issuance_context_path,
        request_path=request_path,
        require_target_absent=False,
    )
    exact_receipt = root / INITIALIZATION_RESTRICTED_ROOT / "initialization-receipt.json"
    if receipt_path != exact_receipt:
        raise SQLiteManifestAuthorityError("initialization receipt path is not exact")
    receipt = cast(
        SQLiteInitializationReceipt,
        _load_canonical_nofollow(
            receipt_path,
            SQLiteInitializationReceipt,
            label="initialization receipt",
            expected_mode=0o600,
        ),
    )
    facts = _restricted_empty_facts(
        repo_root=root,
        schema_dir=schema_dir,
        database_path=database_path,
    )
    if issuance.context_sha256 is None or request.request_sha256 is None:
        raise SQLiteManifestAuthorityError("initialization authority lacks a digest")
    expected = SQLiteInitializationReceipt(
        request_sha256=request.request_sha256,
        state_attestation_sha256=cast(str, state.state_attestation_sha256),
        target_sha256=request.target_sha256,
        binding_sha256=request.binding_sha256,
        token_sha256=_sha256(issuance.expected_token().serialize().encode("ascii")),
        nonce_sha256=_sha256(issuance.nonce.encode("ascii")),
        issuance_context_sha256=issuance.context_sha256,
        ddl_sha256=state.ddl_sha256,
        logical_schema_manifest_sha256=state.logical_schema_manifest_sha256,
        logical_schema_sha256=state.logical_schema_sha256,
        empty_proof_sha256=state.empty_proof_sha256,
        sqlite_version=sqlite3.sqlite_version,
        effective_pragmas=cast(dict[str, int | str], facts["effective_pragmas"]),
        empty_counts=cast(dict[str, int], facts["empty_counts"]),
        freelist_count=cast(Literal[0], facts["freelist_count"]),
        integrity_check="ok",
        foreign_key_check_count=cast(Literal[0], facts["foreign_key_check_count"]),
        sidecars=cast(dict[str, bool], facts["sidecars"]),
        file_identity=cast(SQLiteRestrictedFileIdentity, facts["file_identity"]),
        initialized_at=receipt.initialized_at,
    )
    if receipt != expected:
        raise SQLiteManifestAuthorityError("initialization receipt drifted from live file")
    _assert_sanitized_surface(receipt.model_dump(mode="json"), label="initialization receipt")
    return receipt


def verify_restricted_empty_database(
    *,
    repo_root: Path,
    schema_dir: Path,
    receipt_path: Path,
) -> SQLiteSealReadiness:
    """Reidentify and reattest the exact initialized empty file read-only."""

    root = repo_root.resolve(strict=True)
    restricted_root = root / INITIALIZATION_RESTRICTED_ROOT
    exact_receipt_path = restricted_root / "initialization-receipt.json"
    if receipt_path.resolve(strict=True) != exact_receipt_path:
        raise SQLiteManifestAuthorityError("initialization receipt path is not exact")
    receipt_bytes, _ = _read_regular_nofollow(
        exact_receipt_path,
        label="initialization receipt",
        expected_mode=0o600,
        max_bytes=2 * 1024 * 1024,
    )
    try:
        receipt_hint = SQLiteInitializationReceipt.model_validate(json.loads(receipt_bytes))
    except (json.JSONDecodeError, ValueError) as exc:
        raise SQLiteManifestAuthorityError("initialization receipt contract is invalid") from exc
    if canonical_json_bytes(receipt_hint.model_dump(mode="json")) != receipt_bytes:
        raise SQLiteManifestAuthorityError("initialization receipt is not canonical JSON")
    database_path = root / receipt_hint.file_identity.relative_path

    with _held_sqlite_path_guard(repo_root=root, database_path=database_path) as guarded:
        receipt = verify_initialization_receipt(
            repo_root=root,
            schema_dir=schema_dir,
            state_path=restricted_root / "initialization-state-attestation.json",
            issuance_context_path=restricted_root / "initialization-issuance-context.json",
            request_path=root / "artifacts/public/catalog/v2/sqlite-initialization-request.json",
            receipt_path=exact_receipt_path,
        )
        if guarded != receipt.file_identity:
            raise SQLiteManifestAuthorityError(
                "initialization receipt does not identify the guarded SQLite file"
            )

    split_approval_path = root / "artifacts/restricted/catalog/v2/split/real-split-approval.json"
    split_approval_sha256, split_approval_receipt_sha256 = _split_approval_facts(
        split_approval_path
    )
    readiness = SQLiteSealReadiness(
        initialization_receipt_sha256=_sha256(receipt_bytes),
        initialization_receipt_receipt_sha256=cast(str, receipt.receipt_sha256),
        initialized_file_sha256=receipt.file_identity.sha256,
        ddl_sha256=receipt.ddl_sha256,
        logical_schema_manifest_sha256=receipt.logical_schema_manifest_sha256,
        logical_schema_sha256=receipt.logical_schema_sha256,
        split_approval_sha256=split_approval_sha256,
        split_approval_receipt_sha256=split_approval_receipt_sha256,
        empty_counts=dict(receipt.empty_counts),
        effective_pragmas=dict(receipt.effective_pragmas),
        sidecars=dict(receipt.sidecars),
        file_identity=receipt.file_identity,
    )
    _assert_sanitized_surface(readiness.model_dump(mode="json"), label="seal readiness")
    return readiness


def _seal_member_rows(
    dev_members: Iterable[str], blind_members: Iterable[str]
) -> tuple[dict[str, object], ...]:
    dev = tuple(dev_members)
    blind = tuple(blind_members)
    if len(dev) != 24 or len(blind) != 12 or len(set(dev + blind)) != 36:
        raise SQLiteManifestAuthorityError("reverified split membership counts are not exact")
    return tuple(
        {
            "canonical_place_id": identifier,
            "member_ordinal": ordinal,
            "split": "DEV" if ordinal <= 24 else "BLIND",
        }
        for ordinal, identifier in enumerate(dev + blind, start=1)
    )


def _seal_surface_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return {str(key).casefold() for key in value} | {
            key for child in value.values() for key in _seal_surface_keys(child)
        }
    if isinstance(value, list):
        return {key for child in value for key in _seal_surface_keys(child)}
    return set()


def _assert_seal_surface_safe(
    value: object,
    *,
    label: str,
    protected_member_values: Iterable[str],
) -> None:
    forbidden = {
        "blind_members",
        "canonical_place_id",
        "complement",
        "database_path",
        "database_uri",
        "dev_members",
        "device",
        "inode",
        "member_ids",
        "member_order",
        "members",
        "nonce",
        "ordered_members",
        "ordered_place_ids",
        "path",
        "per_member",
        "per_member_digests",
        "raw_token",
        "uri",
    }
    if _seal_surface_keys(value) & forbidden:
        raise SQLiteManifestAuthorityError(f"{label} contains a forbidden capability field")
    payload = canonical_json_bytes(value)
    if any(identifier.encode("utf-8") in payload for identifier in protected_member_values):
        raise SQLiteManifestAuthorityError(f"{label} contains restricted membership")
    _assert_sanitized_surface(value, label=label)


def _seal_database_state(
    *,
    repo_root: Path,
    readiness: SQLiteSealReadiness,
    request_sha256: str,
    nonce_sha256: str,
    logical_seal_sha256: str,
) -> dict[str, object]:
    database_path = repo_root / readiness.file_identity.relative_path
    with _held_sqlite_path_guard(repo_root=repo_root, database_path=database_path) as identity:
        database_bytes, _ = _read_regular_nofollow(
            database_path,
            label="restricted SQLite database",
            expected_mode=0o600,
            max_bytes=64 * 1024 * 1024,
        )
        connection = _connect_read_only(database_path)
        try:
            state = classify_sqlite_seal_state(
                connection,
                manifest_version=SEAL_MANIFEST_VERSION,
                expected_request_sha256=request_sha256,
                expected_nonce_sha256=nonce_sha256,
                expected_logical_seal_sha256=logical_seal_sha256,
            )
        finally:
            connection.close()
        after_identity = verify_sqlite_file_identity(
            repo_root=repo_root,
            database_path=database_path,
            expected_identity=identity,
        )
        path_stat = database_path.stat(follow_symlinks=False)
    return {
        "database_sha256": _sha256(database_bytes),
        "device": after_identity.device,
        "inode": after_identity.inode,
        "mtime_ns": path_stat.st_mtime_ns,
        "size_bytes": after_identity.size_bytes,
        "seal_state": state.model_dump(mode="json"),
    }


def _seal_target_and_binding(
    state: SQLiteSealAuthorityState,
) -> tuple[dict[str, object], dict[str, object]]:
    target: dict[str, object] = {
        "action": SEAL_ACTION,
        "catalog_revision_sha256": state.catalog_revision_sha256,
        "counts": dict(SEAL_COUNTS),
        "initialized_file_sha256": state.initialized_file_sha256,
        "logical_schema_sha256": state.logical_schema_sha256,
        "logical_seal_input_sha256": state.logical_seal_input_sha256,
        "manifest_version": state.manifest_version,
        "membership_sha256": state.membership_sha256,
        "split_approval_receipt_sha256": state.split_approval_receipt_sha256,
        "split_manifest_sha256": state.split_manifest_sha256,
        "state_attestation_sha256": cast(str, state.state_attestation_sha256),
    }
    target_sha256 = canonical_sha256(target)
    binding: dict[str, object] = {
        "action": SEAL_ACTION,
        "consumer": "itda.sqlite-real-manifest-seal.v1",
        "initialization_receipt_sha256": state.initialization_receipt_sha256,
        "logical_seal_input_sha256": state.logical_seal_input_sha256,
        "split_approval_receipt_sha256": state.split_approval_receipt_sha256,
        "state_attestation_sha256": cast(str, state.state_attestation_sha256),
        "target_sha256": target_sha256,
    }
    return target, binding


def _derive_seal_authority(
    *,
    readiness: SQLiteSealReadiness,
    active_bindings_sha256: str,
    active_parents: dict[str, Sha256],
    split_approval_sha256: str,
    split_approval_receipt_sha256: str,
    split_manifest_sha256: str,
    determinism_report_sha256: str,
    split_replay_sha256: str,
    membership_sha256: str,
    logical_seal_input_sha256: str,
    reviewer_id: str,
    nonce: str,
    issued_at: datetime,
    expires_at: datetime,
) -> tuple[SQLiteSealAuthorityState, SQLiteSealRequest, AuthorityIssuanceContext]:
    state = SQLiteSealAuthorityState(
        readiness_sha256=cast(str, readiness.readiness_sha256),
        initialization_receipt_sha256=readiness.initialization_receipt_sha256,
        initialized_file_sha256=readiness.initialized_file_sha256,
        ddl_sha256=readiness.ddl_sha256,
        logical_schema_manifest_sha256=readiness.logical_schema_manifest_sha256,
        logical_schema_sha256=readiness.logical_schema_sha256,
        catalog_revision_sha256=active_parents["catalog_revision_sha256"],
        catalog_activation_sha256=active_parents["catalog_activation_event_sha256"],
        active_bindings_sha256=active_bindings_sha256,
        split_approval_sha256=split_approval_sha256,
        split_approval_receipt_sha256=split_approval_receipt_sha256,
        split_manifest_sha256=split_manifest_sha256,
        determinism_report_sha256=determinism_report_sha256,
        split_replay_sha256=split_replay_sha256,
        membership_sha256=membership_sha256,
        logical_seal_input_sha256=logical_seal_input_sha256,
        counts=dict(SEAL_COUNTS),
        prepared_at=issued_at,
    )
    target, binding = _seal_target_and_binding(state)
    target_sha256 = canonical_sha256(target)
    binding_sha256 = canonical_sha256(binding)
    request = SQLiteSealRequest(
        state_attestation_sha256=cast(str, state.state_attestation_sha256),
        target_sha256=target_sha256,
        binding_sha256=binding_sha256,
        reviewer_id=reviewer_id,
        initialization_receipt_sha256=state.initialization_receipt_sha256,
        initialized_file_sha256=state.initialized_file_sha256,
        ddl_sha256=state.ddl_sha256,
        logical_schema_manifest_sha256=state.logical_schema_manifest_sha256,
        logical_schema_sha256=state.logical_schema_sha256,
        catalog_revision_sha256=state.catalog_revision_sha256,
        catalog_activation_sha256=state.catalog_activation_sha256,
        split_approval_sha256=state.split_approval_sha256,
        split_approval_receipt_sha256=state.split_approval_receipt_sha256,
        split_manifest_sha256=state.split_manifest_sha256,
        determinism_report_sha256=state.determinism_report_sha256,
        membership_sha256=state.membership_sha256,
        logical_seal_input_sha256=state.logical_seal_input_sha256,
        nonce_sha256=_sha256(nonce.encode("ascii")),
        counts=dict(SEAL_COUNTS),
        issued_at=issued_at,
        expires_at=expires_at,
    )
    issuance = freeze_issuance_context(
        action=SEAL_ACTION,
        request=request.model_dump(exclude={"request_sha256"}, mode="json"),
        state_attestation=state.model_dump(exclude={"state_attestation_sha256"}, mode="json"),
        target=target,
        reviewer_id=reviewer_id,
        binding=binding,
        nonce=nonce,
        issued_at=issued_at,
        expires_at=expires_at,
        reviewer_channel_risk=(
            "Reviewer identity is accepted local-channel metadata, not a "
            "cryptographic identity claim."
        ),
    )
    if request.request_sha256 != issuance.request_sha256:
        raise SQLiteManifestAuthorityError("seal request and issuance context disagree")
    return state, request, issuance


def build_seal_authority(
    *,
    repo_root: Path,
    schema_dir: Path,
    receipt_path: Path,
    materialized_bundle_path: Path,
    split_approval_path: Path,
    reviewer_id: str,
    nonce: str,
    issued_at: datetime,
    expires_at: datetime,
    state_output: Path | None = None,
    issuance_output: Path | None = None,
    request_output: Path | None = None,
) -> tuple[SQLiteSealAuthorityState, SQLiteSealRequest, AuthorityIssuanceContext]:
    """Reverify protected parents and prepare a zero-mutation seal authority."""

    from itda.cli.approve_real_split import (
        DEFAULT_APPROVAL,
        DEFAULT_BUNDLE,
        reverify_materialized_split,
        verify_split_approval,
    )

    root = repo_root.resolve(strict=True)
    issued = require_utc(issued_at, field_name="issued_at")
    expires = require_utc(expires_at, field_name="expires_at")
    if re.fullmatch(r"[0-9a-f]{64}", nonce) is None:
        raise SQLiteManifestAuthorityError("seal nonce is not canonical SHA-256 text")
    exact_bundle = root / DEFAULT_BUNDLE
    exact_approval = root / DEFAULT_APPROVAL
    if (
        materialized_bundle_path.resolve(strict=True) != exact_bundle
        or split_approval_path.resolve(strict=True) != exact_approval
    ):
        raise SQLiteManifestAuthorityError("seal split parent path is not exact")

    outputs = (state_output, issuance_output, request_output)
    if any(path is None for path in outputs) != all(path is None for path in outputs):
        raise SQLiteManifestAuthorityError("seal outputs must be provided together")
    if state_output is not None and issuance_output is not None and request_output is not None:
        restricted_root = root / INITIALIZATION_RESTRICTED_ROOT
        expected_outputs = (
            restricted_root / "seal-state-attestation.json",
            restricted_root / "seal-issuance-context.json",
            root / "artifacts/public/catalog/v2/sqlite-real-manifest-seal-request.json",
        )
        if (state_output, issuance_output, request_output) != expected_outputs:
            raise SQLiteManifestAuthorityError("seal output path is not exact")
        if any(path.exists() or path.is_symlink() for path in expected_outputs):
            raise SQLiteManifestAuthorityError("seal authority output already exists")

    initialization_issuance_path = (
        root / INITIALIZATION_RESTRICTED_ROOT / "initialization-issuance-context.json"
    )
    initialization_issuance = cast(
        AuthorityIssuanceContext,
        _read_canonical_contract(initialization_issuance_path, AuthorityIssuanceContext),
    )
    if hmac.compare_digest(initialization_issuance.nonce, nonce):
        raise SQLiteManifestAuthorityError("seal nonce must differ from initialization nonce")

    readiness = verify_restricted_empty_database(
        repo_root=root,
        schema_dir=schema_dir,
        receipt_path=receipt_path,
    )
    empty_probe = _seal_database_state(
        repo_root=root,
        readiness=readiness,
        request_sha256="0" * 64,
        nonce_sha256="0" * 64,
        logical_seal_sha256="0" * 64,
    )
    if cast(dict[str, object], empty_probe["seal_state"])["classification"] != "EXACT_UNSEALED":
        raise SQLiteManifestAuthorityError("seal target is not exactly unsealed")

    try:
        facts = reverify_materialized_split(root, exact_bundle)
        approval = verify_split_approval(
            exact_approval,
            repo_root=root,
            materialized_bundle_path=exact_bundle,
            require_independent=True,
        )
    except ValueError as exc:
        raise SQLiteManifestAuthorityError("approved split replay failed") from exc
    manifest_sha256 = cast(str, facts.manifest.manifest_sha256)
    report_sha256 = cast(str, facts.report.report_sha256)
    approval_sha256 = cast(str, approval.approval_sha256)
    membership_sha256 = facts.manifest.membership_sha256
    if (
        approval.status != "APPROVED_UNSEALED"
        or approval.seal_sha256 is not None
        or approval.manifest_sha256 != manifest_sha256
        or approval.determinism_report_sha256 != report_sha256
        or approval.split_semantic_sha256 != membership_sha256
        or facts.report.membership_sha256 != membership_sha256
        or approval.active_bindings_sha256 != facts.active_bindings_sha256
    ):
        raise SQLiteManifestAuthorityError("approved split parents are mixed or stale")
    approval_bytes, _ = _read_regular_nofollow(
        exact_approval,
        label="split approval",
        expected_mode=0o600,
        max_bytes=2 * 1024 * 1024,
    )
    if not hmac.compare_digest(_sha256(approval_bytes), readiness.split_approval_sha256):
        raise SQLiteManifestAuthorityError("readiness and replayed approval differ")

    member_rows = _seal_member_rows(
        facts.manifest.dev_members,
        facts.manifest.blind_members,
    )
    logical_input = derive_logical_seal_input_sha256(
        logical_schema_sha256=readiness.logical_schema_sha256,
        catalog_revision_sha256=facts.active_parents["catalog_revision_sha256"],
        split_manifest_sha256=manifest_sha256,
        membership_sha256=membership_sha256,
        ordered_members=member_rows,
    )
    candidate = facts.outcome.candidate
    if candidate is None:
        raise SQLiteManifestAuthorityError("reverified split has no feasible candidate")
    split_replay_sha256 = canonical_sha256(
        {
            "active_bindings_sha256": facts.active_bindings_sha256,
            "candidate_sha256": candidate.candidate_sha256,
            "component_universe_sha256": facts.report.component_universe_sha256,
            "determinism_report_sha256": report_sha256,
            "manifest_sha256": manifest_sha256,
            "materialized_bundle_sha256": facts.bundle.bundle_sha256,
            "membership_sha256": membership_sha256,
            "outcome_sha256": facts.outcome.outcome_sha256,
            "proof_certificate_sha256": facts.report.proof_certificate_sha256,
        }
    )
    derivation_inputs = {
        "readiness": readiness,
        "active_bindings_sha256": facts.active_bindings_sha256,
        "active_parents": facts.active_parents,
        "split_approval_sha256": _sha256(approval_bytes),
        "split_approval_receipt_sha256": approval_sha256,
        "split_manifest_sha256": manifest_sha256,
        "determinism_report_sha256": report_sha256,
        "split_replay_sha256": split_replay_sha256,
        "membership_sha256": membership_sha256,
        "logical_seal_input_sha256": logical_input,
        "reviewer_id": reviewer_id,
        "nonce": nonce,
        "issued_at": issued,
        "expires_at": expires,
    }
    first = _derive_seal_authority(**derivation_inputs)  # type: ignore[arg-type]
    second = _derive_seal_authority(**derivation_inputs)  # type: ignore[arg-type]
    if first != second:
        raise SQLiteManifestAuthorityError("independent seal authority derivations disagree")
    state, request, issuance = first
    protected_values = tuple(facts.manifest.dev_members) + tuple(facts.manifest.blind_members)
    _assert_seal_surface_safe(
        state.model_dump(mode="json"),
        label="seal state",
        protected_member_values=protected_values,
    )
    _assert_seal_surface_safe(
        request.model_dump(mode="json"),
        label="seal request",
        protected_member_values=protected_values,
    )

    after_derivation = _seal_database_state(
        repo_root=root,
        readiness=readiness,
        request_sha256=cast(str, request.request_sha256),
        nonce_sha256=request.nonce_sha256,
        logical_seal_sha256=request.logical_seal_input_sha256,
    )
    if empty_probe != after_derivation:
        empty_comparison = dict(empty_probe)
        after_comparison = dict(after_derivation)
        empty_comparison.pop("seal_state", None)
        after_comparison.pop("seal_state", None)
        if empty_comparison != after_comparison:
            raise SQLiteManifestAuthorityError("seal preparation changed the restricted database")
    if (
        cast(dict[str, object], after_derivation["seal_state"])["classification"]
        != "EXACT_UNSEALED"
    ):
        raise SQLiteManifestAuthorityError("seal preparation changed governed rows")

    if state_output is not None and issuance_output is not None and request_output is not None:
        request_output.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        created: list[Path] = []
        try:
            _write_canonical_exclusive(state_output, state, mode=0o600)
            created.append(state_output)
            _write_canonical_exclusive(issuance_output, issuance, mode=0o600)
            created.append(issuance_output)
            _write_canonical_exclusive(request_output, request, mode=0o644)
            created.append(request_output)
            post_publish = _seal_database_state(
                repo_root=root,
                readiness=readiness,
                request_sha256=cast(str, request.request_sha256),
                nonce_sha256=request.nonce_sha256,
                logical_seal_sha256=request.logical_seal_input_sha256,
            )
            if post_publish != after_derivation:
                raise SQLiteManifestAuthorityError(
                    "seal authority publication changed the restricted database"
                )
        except BaseException:
            for path in reversed(created):
                path.unlink(missing_ok=True)
            raise
    return first


def _load_seal_contract(path: Path, model: type[StrictContract], *, mode: int) -> StrictContract:
    payload, _ = _read_regular_nofollow(
        path,
        label=path.name,
        expected_mode=mode,
        max_bytes=2 * 1024 * 1024,
    )
    try:
        value = model.model_validate(json.loads(payload))
    except (json.JSONDecodeError, ValueError) as exc:
        raise SQLiteManifestAuthorityError(f"{path.name} contract is invalid") from exc
    if canonical_json_bytes(value.model_dump(mode="json")) != payload:
        raise SQLiteManifestAuthorityError(f"{path.name} is not canonical JSON")
    return value


def check_seal_request(
    *,
    repo_root: Path,
    schema_dir: Path,
    receipt_path: Path,
    materialized_bundle_path: Path,
    split_approval_path: Path,
    state_path: Path,
    issuance_context_path: Path,
    request_path: Path,
) -> SQLiteSealRequest:
    """Rebuild and compare a published seal request against all live parents."""

    root = repo_root.resolve(strict=True)
    state = cast(
        SQLiteSealAuthorityState,
        _load_seal_contract(state_path, SQLiteSealAuthorityState, mode=0o600),
    )
    issuance = cast(
        AuthorityIssuanceContext,
        _load_seal_contract(
            issuance_context_path,
            AuthorityIssuanceContext,
            mode=0o600,
        ),
    )
    request = cast(
        SQLiteSealRequest,
        _load_seal_contract(request_path, SQLiteSealRequest, mode=0o644),
    )
    rebuilt_state, rebuilt_request, rebuilt_issuance, _, _, _ = _load_persisted_seal_inputs(
        repo_root=repo_root,
        schema_dir=schema_dir,
        receipt_path=receipt_path,
        materialized_bundle_path=materialized_bundle_path,
        split_approval_path=split_approval_path,
        state_path=root / INITIALIZATION_RESTRICTED_ROOT / "seal-state-attestation.json",
        issuance_context_path=root / INITIALIZATION_RESTRICTED_ROOT / "seal-issuance-context.json",
        request_path=root / "artifacts/public/catalog/v2/sqlite-real-manifest-seal-request.json",
    )
    if (state, request, issuance) != (rebuilt_state, rebuilt_request, rebuilt_issuance):
        raise SQLiteManifestAuthorityError("seal state, request, or issuance context is stale")
    return request


def _load_persisted_seal_inputs(
    *,
    repo_root: Path,
    schema_dir: Path,
    receipt_path: Path,
    materialized_bundle_path: Path,
    split_approval_path: Path,
    state_path: Path,
    issuance_context_path: Path,
    request_path: Path,
) -> tuple[
    SQLiteSealAuthorityState,
    SQLiteSealRequest,
    AuthorityIssuanceContext,
    SQLiteInitializationReceipt,
    tuple[dict[str, object], ...],
    Path,
]:
    """Rederive persisted seal parents without requiring the live file to be empty."""

    from itda.cli.approve_real_split import (
        DEFAULT_APPROVAL,
        DEFAULT_BUNDLE,
        reverify_materialized_split,
        verify_split_approval,
    )

    root = repo_root.resolve(strict=True)
    restricted_root = root / INITIALIZATION_RESTRICTED_ROOT
    exact_receipt = restricted_root / "initialization-receipt.json"
    exact_state = restricted_root / "seal-state-attestation.json"
    exact_issuance = restricted_root / "seal-issuance-context.json"
    exact_request = root / "artifacts/public/catalog/v2/sqlite-real-manifest-seal-request.json"
    if (
        receipt_path.resolve(strict=True) != exact_receipt
        or state_path.resolve(strict=True) != exact_state
        or issuance_context_path.resolve(strict=True) != exact_issuance
        or request_path.resolve(strict=True) != exact_request
        or materialized_bundle_path.resolve(strict=True) != root / DEFAULT_BUNDLE
        or split_approval_path.resolve(strict=True) != root / DEFAULT_APPROVAL
    ):
        raise SQLiteManifestAuthorityError("seal input path is not exact")

    state = cast(
        SQLiteSealAuthorityState,
        _load_seal_contract(exact_state, SQLiteSealAuthorityState, mode=0o600),
    )
    issuance = cast(
        AuthorityIssuanceContext,
        _load_seal_contract(exact_issuance, AuthorityIssuanceContext, mode=0o600),
    )
    request = cast(
        SQLiteSealRequest,
        _load_seal_contract(exact_request, SQLiteSealRequest, mode=0o644),
    )
    initialization_receipt = cast(
        SQLiteInitializationReceipt,
        _load_seal_contract(exact_receipt, SQLiteInitializationReceipt, mode=0o600),
    )
    initialization_bytes, _ = _read_regular_nofollow(
        exact_receipt,
        label="initialization receipt",
        expected_mode=0o600,
        max_bytes=2 * 1024 * 1024,
    )
    split_file_sha256, split_receipt_sha256 = _split_approval_facts(split_approval_path)
    readiness = SQLiteSealReadiness(
        initialization_receipt_sha256=_sha256(initialization_bytes),
        initialization_receipt_receipt_sha256=cast(str, initialization_receipt.receipt_sha256),
        initialized_file_sha256=initialization_receipt.file_identity.sha256,
        ddl_sha256=initialization_receipt.ddl_sha256,
        logical_schema_manifest_sha256=(initialization_receipt.logical_schema_manifest_sha256),
        logical_schema_sha256=initialization_receipt.logical_schema_sha256,
        split_approval_sha256=split_file_sha256,
        split_approval_receipt_sha256=split_receipt_sha256,
        empty_counts=dict(initialization_receipt.empty_counts),
        effective_pragmas=dict(initialization_receipt.effective_pragmas),
        sidecars=dict(initialization_receipt.sidecars),
        file_identity=initialization_receipt.file_identity,
    )

    try:
        facts = reverify_materialized_split(root, root / DEFAULT_BUNDLE)
        approval = verify_split_approval(
            root / DEFAULT_APPROVAL,
            repo_root=root,
            materialized_bundle_path=root / DEFAULT_BUNDLE,
            require_independent=True,
        )
    except ValueError as exc:
        raise SQLiteManifestAuthorityError("approved split replay failed") from exc
    manifest_sha256 = cast(str, facts.manifest.manifest_sha256)
    report_sha256 = cast(str, facts.report.report_sha256)
    approval_sha256 = cast(str, approval.approval_sha256)
    membership_sha256 = facts.manifest.membership_sha256
    if (
        approval.status != "APPROVED_UNSEALED"
        or approval.seal_sha256 is not None
        or approval.manifest_sha256 != manifest_sha256
        or approval.determinism_report_sha256 != report_sha256
        or approval.split_semantic_sha256 != membership_sha256
        or facts.report.membership_sha256 != membership_sha256
        or approval.active_bindings_sha256 != facts.active_bindings_sha256
    ):
        raise SQLiteManifestAuthorityError("approved split parents are mixed or stale")
    approval_bytes, _ = _read_regular_nofollow(
        root / DEFAULT_APPROVAL,
        label="split approval",
        expected_mode=0o600,
        max_bytes=2 * 1024 * 1024,
    )
    member_rows = _seal_member_rows(
        facts.manifest.dev_members,
        facts.manifest.blind_members,
    )
    logical_input = derive_logical_seal_input_sha256(
        logical_schema_sha256=readiness.logical_schema_sha256,
        catalog_revision_sha256=facts.active_parents["catalog_revision_sha256"],
        split_manifest_sha256=manifest_sha256,
        membership_sha256=membership_sha256,
        ordered_members=member_rows,
    )
    candidate = facts.outcome.candidate
    if candidate is None:
        raise SQLiteManifestAuthorityError("reverified split has no feasible candidate")
    split_replay_sha256 = canonical_sha256(
        {
            "active_bindings_sha256": facts.active_bindings_sha256,
            "candidate_sha256": candidate.candidate_sha256,
            "component_universe_sha256": facts.report.component_universe_sha256,
            "determinism_report_sha256": report_sha256,
            "manifest_sha256": manifest_sha256,
            "materialized_bundle_sha256": facts.bundle.bundle_sha256,
            "membership_sha256": membership_sha256,
            "outcome_sha256": facts.outcome.outcome_sha256,
            "proof_certificate_sha256": facts.report.proof_certificate_sha256,
        }
    )
    expected = _derive_seal_authority(
        readiness=readiness,
        active_bindings_sha256=facts.active_bindings_sha256,
        active_parents=facts.active_parents,
        split_approval_sha256=_sha256(approval_bytes),
        split_approval_receipt_sha256=approval_sha256,
        split_manifest_sha256=manifest_sha256,
        determinism_report_sha256=report_sha256,
        split_replay_sha256=split_replay_sha256,
        membership_sha256=membership_sha256,
        logical_seal_input_sha256=logical_input,
        reviewer_id=issuance.reviewer_id,
        nonce=issuance.nonce,
        issued_at=issuance.issued_at,
        expires_at=issuance.expires_at,
    )
    if expected != (state, request, issuance):
        raise SQLiteManifestAuthorityError("seal parents or authority coordinates are stale")
    database_path = root / initialization_receipt.file_identity.relative_path
    return (
        state,
        request,
        issuance,
        initialization_receipt,
        member_rows,
        database_path,
    )


def _seal_metadata(
    state: SQLiteSealAuthorityState,
    *,
    sealed_at: datetime,
) -> dict[str, object]:
    timestamp = require_utc(sealed_at, field_name="sealed_at")
    return {
        "manifest_version": state.manifest_version,
        "catalog_sha256": state.catalog_revision_sha256,
        "split_sha256": state.split_manifest_sha256,
        "membership_sha256": state.membership_sha256,
        "canonicalization_version": "itda-canonical-json-v1",
        "dev_count": 24,
        "blind_count": 12,
        "total_count": 36,
        "sealed_at_utc": timestamp.isoformat().replace("+00:00", "Z"),
    }


def _parse_sealed_at(value: object) -> datetime:
    if not isinstance(value, str):
        raise SQLiteManifestAuthorityError("sealed timestamp is malformed")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SQLiteManifestAuthorityError("sealed timestamp is malformed") from exc
    return require_utc(parsed, field_name="sealed_at")


def _exact_relation(
    connection: sqlite3.Connection,
    *,
    state: SQLiteSealAuthorityState,
    request: SQLiteSealRequest,
    issuance: AuthorityIssuanceContext,
    token_sha256: str,
    member_rows: tuple[dict[str, object], ...],
    sealed_at: datetime,
    logical_seal_sha256: str,
) -> SQLiteSealState:
    request_sha256 = cast(str, request.request_sha256)
    nonce_sha256 = _sha256(issuance.nonce.encode("ascii"))
    classified = classify_sqlite_seal_state(
        connection,
        manifest_version=state.manifest_version,
        expected_request_sha256=request_sha256,
        expected_nonce_sha256=nonce_sha256,
        expected_logical_seal_sha256=logical_seal_sha256,
    )
    if classified.classification != SQLiteSealClassification.EXACT_COMMITTED:
        return classified

    seal = _seal_metadata(state, sealed_at=sealed_at)
    expected_seal = (
        seal["manifest_version"],
        seal["catalog_sha256"],
        seal["split_sha256"],
        seal["membership_sha256"],
        request_sha256,
        state.logical_schema_sha256,
        logical_seal_sha256,
        seal["canonicalization_version"],
        24,
        12,
        36,
        seal["sealed_at_utc"],
    )
    actual_seal = connection.execute(
        """
        SELECT manifest_version, catalog_sha256, split_sha256, membership_sha256,
               authority_request_sha256, logical_schema_sha256,
               logical_seal_sha256, canonicalization_version,
               dev_count, blind_count, total_count, sealed_at_utc
        FROM manifest_seals
        """
    ).fetchone()
    actual_members = connection.execute(
        """
        SELECT member_ordinal, canonical_place_id, split
        FROM manifest_members
        WHERE manifest_version = ?
        ORDER BY member_ordinal
        """,
        (state.manifest_version,),
    ).fetchall()
    expected_members = [
        (
            member["member_ordinal"],
            member["canonical_place_id"],
            member["split"],
        )
        for member in member_rows
    ]
    expected_consumption = (
        state.manifest_version,
        request.binding_sha256,
        nonce_sha256,
        _sha256(SEAL_ACTION.encode("ascii")),
        request_sha256,
        cast(str, state.state_attestation_sha256),
        request.target_sha256,
        token_sha256,
        logical_seal_sha256,
        issuance.reviewer_id,
        seal["sealed_at_utc"],
    )
    actual_consumption = connection.execute(
        """
        SELECT manifest_version, binding_sha256, nonce_sha256, action_sha256,
               request_sha256, state_sha256, target_sha256, token_sha256,
               logical_seal_sha256, reviewer, consumed_at_utc
        FROM authority_consumptions
        """
    ).fetchone()
    if (
        actual_seal != expected_seal
        or actual_members != expected_members
        or actual_consumption != expected_consumption
    ):
        raise SQLiteManifestAuthorityError("committed seal relation is conflicting")
    replayed = derive_logical_seal_sha256(
        logical_schema_sha256=state.logical_schema_sha256,
        seal=seal,
        ordered_members=member_rows,
        authority_request_sha256=request_sha256,
    )
    if not hmac.compare_digest(replayed, logical_seal_sha256):
        raise SQLiteManifestAuthorityError("committed logical seal is conflicting")
    return classified


@contextmanager
def _held_sqlite_write_guard(
    *, repo_root: Path, database_path: Path
) -> Iterator[SQLiteRestrictedFileIdentity]:
    """Hold cooperating guards while allowing the exact main file bytes to change."""

    expected = verify_sqlite_file_identity(
        repo_root=repo_root,
        database_path=database_path,
    )
    directory_descriptor = os.open(
        database_path.parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    file_descriptor = -1
    try:
        fcntl.flock(directory_descriptor, fcntl.LOCK_EX)
        file_descriptor = os.open(
            database_path.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory_descriptor,
        )
        opened = os.fstat(file_descriptor)
        if (opened.st_dev, opened.st_ino) != (expected.device, expected.inode):
            raise SQLiteManifestAuthorityError("SQLite writer guard opened another file")
        yield expected
        after = os.fstat(file_descriptor)
        path_after = database_path.lstat()
        if (after.st_dev, after.st_ino) != (expected.device, expected.inode) or (
            path_after.st_dev,
            path_after.st_ino,
        ) != (expected.device, expected.inode):
            raise SQLiteManifestAuthorityError("SQLite writer path identity changed")
        if (
            not stat.S_ISREG(after.st_mode)
            or stat.S_IMODE(after.st_mode) != 0o600
            or after.st_uid != os.getuid()
            or after.st_nlink != 1
        ):
            raise SQLiteManifestAuthorityError("SQLite writer file facts changed")
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)
        fcntl.flock(directory_descriptor, fcntl.LOCK_UN)
        os.close(directory_descriptor)


def _post_seal_facts(
    *,
    repo_root: Path,
    schema_dir: Path,
    database_path: Path,
    state: SQLiteSealAuthorityState,
    request: SQLiteSealRequest,
    issuance: AuthorityIssuanceContext,
    token_sha256: str,
    member_rows: tuple[dict[str, object], ...],
    sealed_at: datetime,
    logical_seal_sha256: str,
) -> dict[str, object]:
    root = repo_root.resolve(strict=True)
    _require_no_sidecars(database_path)
    identity = verify_sqlite_file_identity(repo_root=root, database_path=database_path)
    manifest, _, _, _ = _schema_initialization_facts(schema_dir)
    connection = _connect_read_only(database_path)
    try:
        replay = _manifest_from_connection(
            connection,
            ddl_sha256=manifest.ddl_sha256,
            collision_proof=manifest.application_id_collision_proof,
        )
        if replay != manifest:
            raise SQLiteManifestAuthorityError("sealed database schema drifted")
        pragmas: dict[str, int | str] = {
            "foreign_keys": cast(int, _scalar(connection, "PRAGMA foreign_keys")),
            "journal_mode": cast(str, _scalar(connection, "PRAGMA journal_mode")),
            "query_only": cast(int, _scalar(connection, "PRAGMA query_only")),
            "trusted_schema": cast(int, _scalar(connection, "PRAGMA trusted_schema")),
        }
        relation = _exact_relation(
            connection,
            state=state,
            request=request,
            issuance=issuance,
            token_sha256=token_sha256,
            member_rows=member_rows,
            sealed_at=sealed_at,
            logical_seal_sha256=logical_seal_sha256,
        )
        integrity_rows = connection.execute("PRAGMA integrity_check").fetchall()
        foreign_key_rows = connection.execute("PRAGMA foreign_key_check").fetchall()
        for statement in (
            "UPDATE manifest_seals SET dev_count = dev_count",
            "DELETE FROM manifest_members WHERE 0",
        ):
            try:
                connection.execute(statement)
            except sqlite3.DatabaseError:
                pass
            else:  # pragma: no cover - query_only must always reject writes
                raise SQLiteManifestAuthorityError("read-only replay accepted a mutation")
    finally:
        connection.close()
    if relation.classification != SQLiteSealClassification.EXACT_COMMITTED:
        raise SQLiteManifestAuthorityError("sealed database is not exact committed state")
    if integrity_rows != [("ok",)] or foreign_key_rows:
        raise SQLiteManifestAuthorityError("sealed database integrity verification failed")
    final_identity = verify_sqlite_file_identity(
        repo_root=root,
        database_path=database_path,
        expected_identity=identity,
    )
    return {
        "effective_pragmas": pragmas,
        "file_identity": final_identity,
        "foreign_key_check_count": 0,
        "integrity_check": "ok",
        "sidecars": _require_no_sidecars(database_path),
    }


def _seal_receipt_from_facts(
    *,
    state: SQLiteSealAuthorityState,
    request: SQLiteSealRequest,
    issuance: AuthorityIssuanceContext,
    token_sha256: str,
    logical_seal_sha256: str,
    sealed_at: datetime,
    facts: dict[str, object],
    disposition: Literal["PUBLISHED", "ALREADY_COMMITTED_VERIFIED"],
) -> SQLiteSealReceipt:
    identity = cast(SQLiteRestrictedFileIdentity, facts["file_identity"])
    receipt = SQLiteSealReceipt(
        request_sha256=cast(str, request.request_sha256),
        state_attestation_sha256=cast(str, state.state_attestation_sha256),
        target_sha256=request.target_sha256,
        binding_sha256=request.binding_sha256,
        token_sha256=token_sha256,
        nonce_sha256=_sha256(issuance.nonce.encode("ascii")),
        initialization_receipt_sha256=state.initialization_receipt_sha256,
        initialized_file_sha256=state.initialized_file_sha256,
        ddl_sha256=state.ddl_sha256,
        logical_schema_manifest_sha256=state.logical_schema_manifest_sha256,
        logical_schema_sha256=state.logical_schema_sha256,
        catalog_revision_sha256=state.catalog_revision_sha256,
        catalog_activation_sha256=state.catalog_activation_sha256,
        split_approval_sha256=state.split_approval_sha256,
        split_approval_receipt_sha256=state.split_approval_receipt_sha256,
        split_manifest_sha256=state.split_manifest_sha256,
        determinism_report_sha256=state.determinism_report_sha256,
        membership_sha256=state.membership_sha256,
        logical_seal_input_sha256=state.logical_seal_input_sha256,
        logical_seal_sha256=logical_seal_sha256,
        database_sha256=identity.sha256,
        database_size_bytes=identity.size_bytes,
        database_uid=identity.uid,
        database_mode="0600",
        database_link_count=1,
        no_follow_result=identity.no_follow_result,
        sqlite_version=sqlite3.sqlite_version,
        effective_pragmas=cast(dict[str, int | str], facts["effective_pragmas"]),
        integrity_check="ok",
        foreign_key_check_count=0,
        sidecars=cast(dict[str, bool], facts["sidecars"]),
        counts=dict(SEAL_COUNTS),
        publication_disposition=disposition,
        sealed_at=sealed_at,
    )
    _assert_seal_surface_safe(
        receipt.model_dump(mode="json"),
        label="seal receipt",
        protected_member_values=(),
    )
    return receipt


def seal_restricted_manifest(
    *,
    raw_token: str,
    repo_root: Path,
    schema_dir: Path,
    receipt_path: Path,
    materialized_bundle_path: Path,
    split_approval_path: Path,
    state_path: Path,
    issuance_context_path: Path,
    request_path: Path,
    seal_receipt_output: Path,
    now: datetime,
) -> SQLiteSealReceipt:
    """Seal EXACT_UNSEALED once or recover EXACT_COMMITTED without SQLite writes."""

    root = repo_root.resolve(strict=True)
    canonical_now = require_utc(now, field_name="now")
    (
        state,
        request,
        issuance,
        _,
        member_rows,
        database_path,
    ) = _load_persisted_seal_inputs(
        repo_root=root,
        schema_dir=schema_dir,
        receipt_path=receipt_path,
        materialized_bundle_path=materialized_bundle_path,
        split_approval_path=split_approval_path,
        state_path=state_path,
        issuance_context_path=issuance_context_path,
        request_path=request_path,
    )
    exact_output = root / INITIALIZATION_RESTRICTED_ROOT / "real-manifest-seal-receipt.json"
    if seal_receipt_output != exact_output:
        raise SQLiteManifestAuthorityError("seal receipt path is not exact")
    target, binding = _seal_target_and_binding(state)
    validated = validate_authority_token(
        raw_token,
        issuance_context=issuance,
        request=request.model_dump(exclude={"request_sha256"}, mode="json"),
        state_attestation=state.model_dump(exclude={"state_attestation_sha256"}, mode="json"),
        target=target,
        binding=binding,
        reviewer_id=issuance.reviewer_id,
        now=canonical_now,
        revocation_tombstones=(),
    )
    request_sha256 = cast(str, request.request_sha256)
    nonce_sha256 = _sha256(issuance.nonce.encode("ascii"))

    before_bytes, before_stat = _read_regular_nofollow(
        database_path,
        label="restricted SQLite database",
        expected_mode=0o600,
        max_bytes=64 * 1024 * 1024,
    )
    connection = _connect_read_only(database_path)
    try:
        raw_counts = {
            table: cast(int, _scalar(connection, f"SELECT count(*) FROM {table}"))
            for table in ("authority_consumptions", "manifest_members", "manifest_seals")
        }
        if raw_counts == SEAL_EMPTY_COUNTS:
            sealed_at = canonical_now
            seal = _seal_metadata(state, sealed_at=sealed_at)
            logical_seal_sha256 = derive_logical_seal_sha256(
                logical_schema_sha256=state.logical_schema_sha256,
                seal=seal,
                ordered_members=member_rows,
                authority_request_sha256=request_sha256,
            )
            classified = classify_sqlite_seal_state(
                connection,
                manifest_version=state.manifest_version,
                expected_request_sha256=request_sha256,
                expected_nonce_sha256=nonce_sha256,
                expected_logical_seal_sha256=logical_seal_sha256,
            )
        elif raw_counts == {
            "authority_consumptions": 1,
            "manifest_members": 36,
            "manifest_seals": 1,
        }:
            sealed_at = _parse_sealed_at(
                _scalar(connection, "SELECT sealed_at_utc FROM manifest_seals")
            )
            seal = _seal_metadata(state, sealed_at=sealed_at)
            logical_seal_sha256 = derive_logical_seal_sha256(
                logical_schema_sha256=state.logical_schema_sha256,
                seal=seal,
                ordered_members=member_rows,
                authority_request_sha256=request_sha256,
            )
            classified = _exact_relation(
                connection,
                state=state,
                request=request,
                issuance=issuance,
                token_sha256=validated.token_sha256,
                member_rows=member_rows,
                sealed_at=sealed_at,
                logical_seal_sha256=logical_seal_sha256,
            )
        else:
            classified = classify_sqlite_seal_state(
                connection,
                manifest_version=state.manifest_version,
                expected_request_sha256=request_sha256,
                expected_nonce_sha256=nonce_sha256,
                expected_logical_seal_sha256="0" * 64,
            )
            sealed_at = canonical_now
            logical_seal_sha256 = "0" * 64
    finally:
        connection.close()

    if classified.classification in {
        SQLiteSealClassification.PARTIAL,
        SQLiteSealClassification.CONFLICTING,
    }:
        raise SQLiteManifestAuthorityError(
            f"seal relation is {classified.classification.value}; repair is forbidden"
        )

    disposition: Literal["PUBLISHED", "ALREADY_COMMITTED_VERIFIED"]
    if classified.classification == SQLiteSealClassification.EXACT_UNSEALED:
        if seal_receipt_output.exists() or seal_receipt_output.is_symlink():
            raise SQLiteManifestAuthorityError("seal receipt exists before commit")
        manifest, _, _, _ = _schema_initialization_facts(schema_dir)
        with _held_sqlite_write_guard(repo_root=root, database_path=database_path):
            writer = sqlite3.connect(
                f"{database_path.as_uri()}?mode=rw",
                uri=True,
                autocommit=True,
                timeout=0.25,
            )
            try:
                mode = cast(str, _scalar(writer, "PRAGMA journal_mode=DELETE"))
                writer.execute("PRAGMA foreign_keys=ON")
                writer.execute("PRAGMA trusted_schema=OFF")
                if (
                    mode.lower() != "delete"
                    or _scalar(writer, "PRAGMA foreign_keys") != 1
                    or _scalar(writer, "PRAGMA trusted_schema") != 0
                ):
                    raise SQLiteManifestAuthorityError("seal writer PRAGMAs are not exact")
                replay = _manifest_from_connection(
                    writer,
                    ddl_sha256=manifest.ddl_sha256,
                    collision_proof=manifest.application_id_collision_proof,
                )
                if replay != manifest:
                    raise SQLiteManifestAuthorityError("seal writer schema drifted")
                writer.execute("BEGIN IMMEDIATE")
                try:
                    locked = classify_sqlite_seal_state(
                        writer,
                        manifest_version=state.manifest_version,
                        expected_request_sha256=request_sha256,
                        expected_nonce_sha256=nonce_sha256,
                        expected_logical_seal_sha256=logical_seal_sha256,
                    )
                    if locked.classification != SQLiteSealClassification.EXACT_UNSEALED:
                        raise SQLiteManifestAuthorityError("seal state changed before commit")
                    writer.execute(
                        """
                        INSERT INTO manifest_seals (
                            manifest_version, catalog_sha256, split_sha256,
                            membership_sha256, authority_request_sha256,
                            logical_schema_sha256, logical_seal_sha256,
                            canonicalization_version, dev_count, blind_count,
                            total_count, sealed_at_utc
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            seal["manifest_version"],
                            seal["catalog_sha256"],
                            seal["split_sha256"],
                            seal["membership_sha256"],
                            request_sha256,
                            state.logical_schema_sha256,
                            logical_seal_sha256,
                            seal["canonicalization_version"],
                            24,
                            12,
                            36,
                            seal["sealed_at_utc"],
                        ),
                    )
                    writer.executemany(
                        """
                        INSERT INTO manifest_members (
                            manifest_version, member_ordinal,
                            canonical_place_id, split
                        ) VALUES (?, ?, ?, ?)
                        """,
                        [
                            (
                                state.manifest_version,
                                member["member_ordinal"],
                                member["canonical_place_id"],
                                member["split"],
                            )
                            for member in member_rows
                        ],
                    )
                    writer.execute(
                        """
                        INSERT INTO authority_consumptions (
                            manifest_version, binding_sha256, nonce_sha256,
                            action_sha256, request_sha256, state_sha256,
                            target_sha256, token_sha256, logical_seal_sha256,
                            reviewer, consumed_at_utc
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            state.manifest_version,
                            request.binding_sha256,
                            nonce_sha256,
                            _sha256(SEAL_ACTION.encode("ascii")),
                            request_sha256,
                            cast(str, state.state_attestation_sha256),
                            request.target_sha256,
                            validated.token_sha256,
                            logical_seal_sha256,
                            issuance.reviewer_id,
                            seal["sealed_at_utc"],
                        ),
                    )
                    committed = _exact_relation(
                        writer,
                        state=state,
                        request=request,
                        issuance=issuance,
                        token_sha256=validated.token_sha256,
                        member_rows=member_rows,
                        sealed_at=sealed_at,
                        logical_seal_sha256=logical_seal_sha256,
                    )
                    if committed.classification != SQLiteSealClassification.EXACT_COMMITTED:
                        raise SQLiteManifestAuthorityError("seal transaction did not rederive")
                    writer.execute("COMMIT")
                except BaseException:
                    if writer.in_transaction:
                        writer.execute("ROLLBACK")
                    raise
            finally:
                writer.close()
        disposition = "PUBLISHED"
    else:
        after_bytes, after_stat = _read_regular_nofollow(
            database_path,
            label="restricted SQLite database",
            expected_mode=0o600,
            max_bytes=64 * 1024 * 1024,
        )
        if (
            before_bytes != after_bytes
            or before_stat.st_size != after_stat.st_size
            or before_stat.st_mtime_ns != after_stat.st_mtime_ns
            or (before_stat.st_dev, before_stat.st_ino) != (after_stat.st_dev, after_stat.st_ino)
        ):
            raise SQLiteManifestAuthorityError("exact-existing recovery changed SQLite bytes")
        disposition = "ALREADY_COMMITTED_VERIFIED"

    facts = _post_seal_facts(
        repo_root=root,
        schema_dir=schema_dir,
        database_path=database_path,
        state=state,
        request=request,
        issuance=issuance,
        token_sha256=validated.token_sha256,
        member_rows=member_rows,
        sealed_at=sealed_at,
        logical_seal_sha256=logical_seal_sha256,
    )
    if seal_receipt_output.exists() or seal_receipt_output.is_symlink():
        existing = cast(
            SQLiteSealReceipt,
            _load_seal_contract(
                seal_receipt_output,
                SQLiteSealReceipt,
                mode=0o600,
            ),
        )
        expected_existing = _seal_receipt_from_facts(
            state=state,
            request=request,
            issuance=issuance,
            token_sha256=validated.token_sha256,
            logical_seal_sha256=logical_seal_sha256,
            sealed_at=sealed_at,
            facts=facts,
            disposition=existing.publication_disposition,
        )
        if existing != expected_existing:
            raise SQLiteManifestAuthorityError("existing seal receipt is conflicting")
        return existing
    receipt = _seal_receipt_from_facts(
        state=state,
        request=request,
        issuance=issuance,
        token_sha256=validated.token_sha256,
        logical_seal_sha256=logical_seal_sha256,
        sealed_at=sealed_at,
        facts=facts,
        disposition=disposition,
    )
    _write_canonical_exclusive(seal_receipt_output, receipt, mode=0o600)
    return receipt


def verify_seal_receipt(
    *,
    repo_root: Path,
    schema_dir: Path,
    receipt_path: Path,
    materialized_bundle_path: Path,
    split_approval_path: Path,
    state_path: Path,
    issuance_context_path: Path,
    request_path: Path,
    seal_receipt_path: Path,
) -> SQLiteSealReceipt:
    """Verify the sanitized receipt and exact committed live file read-only."""

    root = repo_root.resolve(strict=True)
    (
        state,
        request,
        issuance,
        _,
        member_rows,
        database_path,
    ) = _load_persisted_seal_inputs(
        repo_root=root,
        schema_dir=schema_dir,
        receipt_path=receipt_path,
        materialized_bundle_path=materialized_bundle_path,
        split_approval_path=split_approval_path,
        state_path=state_path,
        issuance_context_path=issuance_context_path,
        request_path=request_path,
    )
    exact_path = root / INITIALIZATION_RESTRICTED_ROOT / "real-manifest-seal-receipt.json"
    if seal_receipt_path.resolve(strict=True) != exact_path:
        raise SQLiteManifestAuthorityError("seal receipt path is not exact")
    receipt = cast(
        SQLiteSealReceipt,
        _load_seal_contract(exact_path, SQLiteSealReceipt, mode=0o600),
    )
    sealed_at = receipt.sealed_at
    seal = _seal_metadata(state, sealed_at=sealed_at)
    logical_seal_sha256 = derive_logical_seal_sha256(
        logical_schema_sha256=state.logical_schema_sha256,
        seal=seal,
        ordered_members=member_rows,
        authority_request_sha256=cast(str, request.request_sha256),
    )
    expected_token_sha256 = _sha256(issuance.expected_token().serialize().encode("ascii"))
    facts = _post_seal_facts(
        repo_root=root,
        schema_dir=schema_dir,
        database_path=database_path,
        state=state,
        request=request,
        issuance=issuance,
        token_sha256=expected_token_sha256,
        member_rows=member_rows,
        sealed_at=sealed_at,
        logical_seal_sha256=logical_seal_sha256,
    )
    expected = _seal_receipt_from_facts(
        state=state,
        request=request,
        issuance=issuance,
        token_sha256=expected_token_sha256,
        logical_seal_sha256=logical_seal_sha256,
        sealed_at=sealed_at,
        facts=facts,
        disposition=receipt.publication_disposition,
    )
    if receipt != expected:
        raise SQLiteManifestAuthorityError("seal receipt drifted from live committed state")
    return receipt


__all__ = [
    "APPLICATION_ID",
    "APPLICATION_ID_HEX",
    "APPLICATION_ID_REGISTRY_SHA256",
    "APPLICATION_ID_RETRIEVED_ON",
    "APPLICATION_ID_SOURCE_URL",
    "ApplicationIdCollisionProof",
    "INITIALIZATION_ACTION",
    "INITIALIZATION_RESTRICTED_ROOT",
    "RESEARCH_ATTESTATION_SHA256",
    "RESEARCH_VALID_THROUGH",
    "SQLiteEmptyProof",
    "SQLiteFileIdentity",
    "SQLiteInitializationReceipt",
    "SQLiteInitializationRequest",
    "SQLiteInitializationState",
    "SQLiteLogicalSchemaManifest",
    "SQLiteManifestAuthorityError",
    "SQLiteSealAuthorityState",
    "SQLiteSealClassification",
    "SQLiteSealReadiness",
    "SQLiteSealReceipt",
    "SQLiteSealRequest",
    "SQLiteSealState",
    "build_initialization_authority",
    "build_seal_authority",
    "build_tracked_empty_projection",
    "check_initialization_request",
    "classify_sqlite_seal_state",
    "check_seal_request",
    "derive_logical_seal_input_sha256",
    "derive_logical_seal_sha256",
    "initialize_restricted_empty_database",
    "seal_restricted_manifest",
    "verify_application_id_collision",
    "verify_empty_projection",
    "verify_initialization_receipt",
    "verify_restricted_empty_database",
    "verify_seal_receipt",
    "verify_sqlite_file_identity",
]
