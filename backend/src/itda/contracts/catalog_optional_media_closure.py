"""Fail-closed contracts for optional-media representation closure."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import Field, field_validator, model_validator

from itda.contracts.base import Sha256, StrictContract
from itda.contracts.catalog_optional_media_frontier import OptionalMediaFrontier
from itda.contracts.catalog_readiness import RepresentationGroup
from itda.domain.canonical import canonical_sha256

CLOSURE_PLAN_SCHEMA_VERSION = "itda.catalog-optional-media-closure-plan.v1"
CLOSURE_EVIDENCE_SCHEMA_VERSION = "itda.catalog-optional-media-closure-evidence.v1"
CLOSABLE_EVIDENCE_TYPES = ("description", "operating_information")


class ClosureExecutionMode(StrEnum):
    """The complete, non-extensible closure dispatch."""

    CAPTURED_REPLAY = "captured_replay"
    FRESH_COLLECTION = "fresh_collection"
    TERMINAL = "terminal"


class ClosureEvidenceCoverage(StrictContract):
    """Exact source-neutral deficits one route claims it can close."""

    place_entity_id: Annotated[str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")]
    provider_candidate_id: Annotated[
        str,
        Field(strict=True, pattern=r"^candidate:tour-api:[0-9]+$"),
    ]
    evidence_types: tuple[Literal["description", "operating_information"], ...]

    @model_validator(mode="after")
    def validate_coverage(self) -> Self:
        expected = tuple(
            field for field in CLOSABLE_EVIDENCE_TYPES if field in set(self.evidence_types)
        )
        if not expected or self.evidence_types != expected:
            raise ValueError("closure evidence types must be unique frozen order")
        return self


class ClosureTargetRow(StrictContract):
    """One deterministic source-neutral target selected from the frontier."""

    place_entity_id: Annotated[str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")]
    provider_candidate_id: Annotated[
        str,
        Field(strict=True, pattern=r"^candidate:tour-api:[0-9]+$"),
    ]
    representation_primary_group: RepresentationGroup
    candidate_row_sha256: Sha256
    non_image_deficits: tuple[Literal["description", "operating_information"], ...]
    frontier_deficit_sha256: Sha256
    target_row_sha256: Sha256

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        expected_deficits = tuple(
            field for field in CLOSABLE_EVIDENCE_TYPES if field in set(self.non_image_deficits)
        )
        if not expected_deficits or self.non_image_deficits != expected_deficits:
            raise ValueError("closure target contains a non-addressable or reordered deficit")
        expected = canonical_sha256(self.model_dump(exclude={"target_row_sha256"}, mode="json"))
        if self.target_row_sha256 != expected:
            raise ValueError("closure target row digest drifted")
        return self


class CapturedEvidenceRoute(StrictContract):
    """Already captured evidence that is independently rights/identity admissible."""

    schema_version: Literal["itda.catalog-optional-media-captured-route.v1"] = (
        "itda.catalog-optional-media-captured-route.v1"
    )
    source_id: Annotated[
        str,
        Field(strict=True, pattern=r"^captured:[A-Za-z0-9._:-]+$", max_length=200),
    ]
    source_root_sha256: Sha256
    evidence_root_sha256: Sha256
    rights_manifest_sha256: Sha256
    identity_manifest_sha256: Sha256
    lineage_manifest_sha256: Sha256
    manifest_relative_path: Annotated[
        str,
        Field(strict=True, pattern=r"^[A-Za-z0-9._/-]+$", min_length=1, max_length=500),
    ]
    evidence_relative_paths: Annotated[
        tuple[
            Annotated[
                str,
                Field(
                    strict=True,
                    pattern=r"^[A-Za-z0-9._/-]+$",
                    min_length=1,
                    max_length=500,
                ),
            ],
            ...,
        ],
        Field(min_length=1, max_length=60),
    ]
    coverage: Annotated[tuple[ClosureEvidenceCoverage, ...], Field(min_length=1)]
    admissible: Literal[True]
    authority_required: Literal[False] = False
    credential_required: Literal[False] = False
    provider_traffic_allowed: Literal[False] = False
    attempt_inventory: tuple[()] = ()

    @model_validator(mode="after")
    def validate_captured_route(self) -> Self:
        paths = (self.manifest_relative_path, *self.evidence_relative_paths)
        if any(path.startswith("/") or ".." in path.split("/") for path in paths):
            raise ValueError("captured evidence path escapes its bound root")
        if self.evidence_relative_paths != tuple(sorted(set(self.evidence_relative_paths))):
            raise ValueError("captured evidence paths must use unique canonical order")
        ids = tuple(row.place_entity_id for row in self.coverage)
        if ids != tuple(sorted(ids)) or len(set(ids)) != len(ids):
            raise ValueError("captured evidence coverage must use unique source-neutral order")
        return self


class FreshCollectionBounds(StrictContract):
    """Immutable one-operation provider boundary."""

    per_attempt_timeout_seconds: Literal[300] = 300
    max_attempts: Annotated[int, Field(strict=True, ge=1, le=3)] = 2
    retry_classes: tuple[Literal["TRANSPORT", "HTTP_408", "HTTP_429", "HTTP_5XX"], ...] = (
        "TRANSPORT",
        "HTTP_408",
        "HTTP_429",
        "HTTP_5XX",
    )
    max_response_bytes: Annotated[int, Field(strict=True, ge=1, le=16 * 1024 * 1024)] = (
        2 * 1024 * 1024
    )
    max_items: Annotated[int, Field(strict=True, ge=1, le=60)] = 60
    max_json_depth: Annotated[int, Field(strict=True, ge=1, le=64)] = 16
    redirects_allowed: Literal[False] = False


class FreshCollectionRoute(StrictContract):
    """One approved official-source request candidate."""

    schema_version: Literal["itda.catalog-optional-media-fresh-route.v1"] = (
        "itda.catalog-optional-media-fresh-route.v1"
    )
    source_id: Annotated[
        str,
        Field(strict=True, pattern=r"^official:[A-Za-z0-9._:-]+$", max_length=200),
    ]
    provider: Literal["TOUR_API", "ODII", "TOURISM_PHOTO"]
    official_dataset_id: Literal["15101578", "15101971", "15101914"]
    source_manifest_sha256: Sha256
    source_approval_sha256: Sha256
    deterministic_id_join_sha256: Sha256
    host: Literal["apis.data.go.kr"]
    path: Annotated[
        str,
        Field(
            strict=True,
            pattern=r"^/[A-Za-z0-9._/-]+$",
            min_length=2,
            max_length=300,
        ),
    ]
    operation: Literal[
        "detailCommon2",
        "detailIntro2",
        "themeSearchList",
        "themeBasedList",
        "storyBasedList",
    ]
    secret_free_parameters: dict[
        Annotated[str, Field(strict=True, min_length=1, max_length=100)],
        Annotated[str, Field(strict=True, max_length=500)],
    ]
    request_identity_sha256: Sha256 | None = None
    predecessor_request_identity_sha256: Sha256 | None
    predecessor_secret_free_parameters: (
        dict[
            Annotated[str, Field(strict=True, min_length=1, max_length=100)],
            Annotated[str, Field(strict=True, max_length=500)],
        ]
        | None
    ) = None
    changed_fields: tuple[
        Annotated[
            str,
            Field(strict=True, pattern=r"^[A-Za-z0-9_.-]+$", min_length=1, max_length=100),
        ],
        ...,
    ]
    expected_evidence_types: tuple[
        Literal["description", "operating_information"],
        ...,
    ]
    coverage: Annotated[tuple[ClosureEvidenceCoverage, ...], Field(min_length=1)]
    bounds: FreshCollectionBounds
    credential_reference: Literal[
        ".secrets/itda-api.env:TOUR_API_SERVICE_KEY",
        ".secrets/itda-odii.env:ODII_SERVICE_KEY",
    ]
    alternate_approved_source: Annotated[bool, Field(strict=True)]

    @field_validator("secret_free_parameters")
    @classmethod
    def parameters_exclude_secrets(cls, value: dict[str, str]) -> dict[str, str]:
        fragments = ("servicekey", "api_key", "apikey", "token", "secret", "authorization")
        if any(any(fragment in key.casefold() for fragment in fragments) for key in value):
            raise ValueError("fresh collection parameters must be secret-free")
        return value

    @model_validator(mode="after")
    def validate_route(self) -> Self:
        expected_dataset = {
            "TOUR_API": "15101578",
            "ODII": "15101971",
            "TOURISM_PHOTO": "15101914",
        }[self.provider]
        if self.official_dataset_id != expected_dataset:
            raise ValueError("fresh collection dataset does not match provider")
        provider_contract = {
            "TOUR_API": {
                "operations": {"detailCommon2", "detailIntro2"},
                "path_prefix": "/B551011/KorService2/",
                "credential": ".secrets/itda-api.env:TOUR_API_SERVICE_KEY",
            },
            "ODII": {
                "operations": {"themeSearchList", "themeBasedList", "storyBasedList"},
                "path_prefix": "/B551011/Odii/",
                "credential": ".secrets/itda-odii.env:ODII_SERVICE_KEY",
            },
            "TOURISM_PHOTO": {
                "operations": set(),
                "path_prefix": "/B551011/PhotoGalleryService1/",
                "credential": ".secrets/itda-api.env:TOUR_API_SERVICE_KEY",
            },
        }[self.provider]
        if (
            self.operation not in provider_contract["operations"]
            or self.path != f"{provider_contract['path_prefix']}{self.operation}"
            or self.credential_reference != provider_contract["credential"]
        ):
            raise ValueError("fresh route provider, path, operation, or credential drifted")
        if self.expected_evidence_types != tuple(
            field for field in CLOSABLE_EVIDENCE_TYPES if field in set(self.expected_evidence_types)
        ):
            raise ValueError("fresh route evidence types changed frozen order")
        coverage_types = {item for row in self.coverage for item in row.evidence_types}
        if not coverage_types <= set(self.expected_evidence_types):
            raise ValueError("fresh route coverage exceeds expected evidence types")
        ids = tuple(row.place_entity_id for row in self.coverage)
        if ids != tuple(sorted(ids)) or len(set(ids)) != len(ids):
            raise ValueError("fresh route coverage must use unique source-neutral order")
        if self.alternate_approved_source and self.changed_fields:
            raise ValueError("alternate source cannot masquerade as a changed request")
        if self.changed_fields != tuple(sorted(set(self.changed_fields))):
            raise ValueError("changed fields must use unique canonical order")
        if self.alternate_approved_source and (
            self.predecessor_request_identity_sha256 is not None
            or self.predecessor_secret_free_parameters is not None
        ):
            raise ValueError("alternate source cannot claim same-provider request ancestry")
        if self.predecessor_secret_free_parameters is None:
            if self.predecessor_request_identity_sha256 is not None or self.changed_fields:
                raise ValueError("changed request requires exact predecessor parameters")
        else:
            expected_changed = tuple(
                sorted(
                    key
                    for key in (
                        set(self.secret_free_parameters)
                        | set(self.predecessor_secret_free_parameters)
                    )
                    if self.secret_free_parameters.get(key)
                    != self.predecessor_secret_free_parameters.get(key)
                )
            )
            if self.changed_fields != expected_changed:
                raise ValueError("changed fields do not prove the exact request semantic delta")
            predecessor_payload = self._request_identity_payload(
                self.predecessor_secret_free_parameters
            )
            expected_predecessor = canonical_sha256(predecessor_payload)
            if self.predecessor_request_identity_sha256 is None:
                object.__setattr__(
                    self,
                    "predecessor_request_identity_sha256",
                    expected_predecessor,
                )
            elif self.predecessor_request_identity_sha256 != expected_predecessor:
                raise ValueError("predecessor request identity is not canonically derived")
        current_identity = canonical_sha256(
            self._request_identity_payload(self.secret_free_parameters)
        )
        if self.request_identity_sha256 is None:
            object.__setattr__(self, "request_identity_sha256", current_identity)
        elif self.request_identity_sha256 != current_identity:
            raise ValueError("fresh request identity is not canonically derived")
        rows_value = self.secret_free_parameters.get("numOfRows")
        if rows_value is not None:
            try:
                rows = int(rows_value)
            except ValueError as exc:
                raise ValueError("numOfRows must be an integer") from exc
            if rows < 1 or rows > self.bounds.max_items:
                raise ValueError("numOfRows exceeds the bound item ceiling")
        return self

    def _request_identity_payload(self, parameters: dict[str, str]) -> dict[str, Any]:
        return {
            "schema_version": "itda.catalog-optional-media-request-identity.v1",
            "source_id": self.source_id,
            "provider": self.provider,
            "official_dataset_id": self.official_dataset_id,
            "source_manifest_sha256": self.source_manifest_sha256,
            "source_approval_sha256": self.source_approval_sha256,
            "deterministic_id_join_sha256": self.deterministic_id_join_sha256,
            "host": self.host,
            "path": self.path,
            "operation": self.operation,
            "secret_free_parameters": parameters,
            "expected_evidence_types": self.expected_evidence_types,
            "coverage": [row.model_dump(mode="json") for row in self.coverage],
            "bounds": self.bounds.model_dump(mode="json"),
        }


class ClosureAuthorityRequest(StrictContract):
    """Secret-free scope that Plan 54 may use to request seven-field authority."""

    schema_version: Literal["itda.catalog-optional-media-authority-request.v1"] = (
        "itda.catalog-optional-media-authority-request.v1"
    )
    operation: Literal["catalog-optional-media-close"]
    request_sha256: Sha256
    state_attestation_sha256: Sha256
    target_sha256: Sha256
    binding_sha256: Sha256
    reviewer_id: None = None
    nonce: None = None
    token_issued: Literal[False] = False
    request_sha256_is_secret_free: Literal[True] = True


TerminalReasonCode = Literal[
    "CAPTURED_ADMISSIBLE_EVIDENCE_ABSENT",
    "SAME_REQUEST_IDENTITY_EXHAUSTED",
    "NO_APPROVED_ALTERNATE_OFFICIAL_SOURCE",
    "NO_ROUTE_COVERS_EXACT_TARGET",
    "REPRESENTATION_TARGET_SET_INFEASIBLE",
]


class NonAddressableClosureTerminal(StrictContract):
    """Immutable no-route terminal; it creates no human or runtime capability."""

    schema_version: Literal["itda.catalog-optional-media-closure-terminal.v1"] = (
        "itda.catalog-optional-media-closure-terminal.v1"
    )
    code: Literal["NON_ADDRESSABLE_REPRESENTATION_FRONTIER"]
    exit_code: Literal[24]
    frontier_sha256: Sha256
    universe_root_sha256: Sha256
    target_rows: tuple[ClosureTargetRow, ...]
    target_root_sha256: Sha256
    reason_codes: tuple[TerminalReasonCode, ...]
    authority_request_created: Literal[False]
    credential_accessed: Literal[False]
    provider_traffic_performed: Literal[False]
    plan54_reachable: Literal[False]
    terminal_sha256: Sha256

    @model_validator(mode="after")
    def validate_terminal(self) -> Self:
        expected_reason_order = tuple(
            reason
            for reason in (
                "CAPTURED_ADMISSIBLE_EVIDENCE_ABSENT",
                "SAME_REQUEST_IDENTITY_EXHAUSTED",
                "NO_APPROVED_ALTERNATE_OFFICIAL_SOURCE",
                "NO_ROUTE_COVERS_EXACT_TARGET",
                "REPRESENTATION_TARGET_SET_INFEASIBLE",
            )
            if reason in set(self.reason_codes)
        )
        if not expected_reason_order or self.reason_codes != expected_reason_order:
            raise ValueError("closure terminal reasons must use frozen unique order")
        if self.target_root_sha256 != canonical_sha256(
            [row.model_dump(mode="json") for row in self.target_rows]
        ):
            raise ValueError("closure terminal target root drifted")
        expected = canonical_sha256(self.model_dump(exclude={"terminal_sha256"}, mode="json"))
        if self.terminal_sha256 != expected:
            raise ValueError("closure terminal digest drifted")
        return self


class ClosurePlan(StrictContract):
    """One mutually exclusive closure decision."""

    schema_version: Literal["itda.catalog-optional-media-closure-plan.v1"] = (
        "itda.catalog-optional-media-closure-plan.v1"
    )
    execution_mode: ClosureExecutionMode
    frontier_sha256: Sha256
    universe_root_sha256: Sha256
    frontier: OptionalMediaFrontier
    provider_ids_by_place: dict[str, str]
    attempted_provider_ids: tuple[str, ...]
    target_rows: tuple[ClosureTargetRow, ...]
    target_root_sha256: Sha256
    captured_replay: CapturedEvidenceRoute | None
    fresh_collection: FreshCollectionRoute | None
    authority_request: ClosureAuthorityRequest | None
    terminal: NonAddressableClosureTerminal | None
    authority_required: Annotated[bool, Field(strict=True)]
    credential_required: Annotated[bool, Field(strict=True)]
    provider_traffic_allowed: Literal[False]
    attempt_inventory: tuple[()] = ()
    plan54_reachable: Annotated[bool, Field(strict=True)]
    plan_sha256: Sha256

    @model_validator(mode="after")
    def validate_plan(self) -> Self:
        if self.frontier_sha256 != self.frontier.frontier_sha256:
            raise ValueError("closure plan frontier binding drifted")
        if self.universe_root_sha256 != self.frontier.universe_root_sha256:
            raise ValueError("closure plan universe binding drifted")
        if self.attempted_provider_ids != tuple(sorted(set(self.attempted_provider_ids))):
            raise ValueError("closure attempted-provider inventory is not canonical")
        if self.target_root_sha256 != canonical_sha256(
            [row.model_dump(mode="json") for row in self.target_rows]
        ):
            raise ValueError("closure plan target root drifted")
        if self.execution_mode is ClosureExecutionMode.CAPTURED_REPLAY:
            valid = (
                self.captured_replay is not None
                and self.fresh_collection is None
                and self.authority_request is None
                and self.terminal is None
                and not self.authority_required
                and not self.credential_required
                and self.plan54_reachable
            )
            label = "captured_replay"
        elif self.execution_mode is ClosureExecutionMode.FRESH_COLLECTION:
            valid = (
                self.captured_replay is None
                and self.fresh_collection is not None
                and self.authority_request is not None
                and self.terminal is None
                and self.authority_required
                and self.credential_required
                and self.plan54_reachable
            )
            label = "fresh_collection"
        else:
            valid = (
                self.captured_replay is None
                and self.fresh_collection is None
                and self.authority_request is None
                and self.terminal is not None
                and not self.authority_required
                and not self.credential_required
                and not self.plan54_reachable
            )
            label = "terminal"
        if not valid:
            raise ValueError(f"{label} fields are mixed, missing, or capability-inconsistent")
        expected = canonical_sha256(self.model_dump(exclude={"plan_sha256"}, mode="json"))
        if self.plan_sha256 != expected:
            raise ValueError("closure plan digest drifted")
        return self


class ClosureNormalizedEvidenceRow(StrictContract):
    """One rights- and identity-bound normalized non-image closure row."""

    place_entity_id: Annotated[str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")]
    provider_candidate_id: Annotated[
        str,
        Field(strict=True, pattern=r"^candidate:tour-api:[0-9]+$"),
    ]
    target_row_sha256: Sha256
    normalized_facts: dict[
        Literal["description", "operating_information"],
        Annotated[str, Field(strict=True, min_length=1, max_length=20_000)],
    ]
    source_manifest_sha256: Sha256
    evidence_sha256: Sha256
    rights_manifest_sha256: Sha256
    identity_manifest_sha256: Sha256
    lineage_manifest_sha256: Sha256
    response_sha256: Sha256
    rejected_raw_sha256: Sha256 | None = None
    row_sha256: Sha256

    @model_validator(mode="after")
    def validate_normalized_row(self) -> Self:
        if not self.normalized_facts:
            raise ValueError("closure evidence row requires one normalized fact")
        expected = canonical_sha256(self.model_dump(exclude={"row_sha256"}, mode="json"))
        if self.row_sha256 != expected:
            raise ValueError("closure normalized evidence row digest drifted")
        return self


class ClosureAttemptReceipt(StrictContract):
    """Secret-free append-only provider attempt inventory."""

    ordinal: Annotated[int, Field(strict=True, ge=1, le=3)]
    request_identity_sha256: Sha256
    provider: Literal["TOUR_API", "ODII"]
    operation: Literal[
        "detailCommon2",
        "detailIntro2",
        "themeSearchList",
        "themeBasedList",
        "storyBasedList",
    ]
    http_status: Annotated[int | None, Field(strict=True, ge=100, le=599)]
    outcome: Literal["SUCCESS", "TRANSIENT_RETRY", "TERMINAL_FAILURE"]
    raw_response_sha256: Sha256
    private_response_ref_sha256: Sha256
    safe_headers: dict[
        Literal["content-type", "retry-after", "x-ratelimit-limit", "x-ratelimit-remaining"],
        Annotated[str, Field(strict=True, max_length=500)],
    ]
    receipt_sha256: Sha256

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"receipt_sha256"}, mode="json"))
        if self.receipt_sha256 != expected:
            raise ValueError("closure attempt receipt digest drifted")
        return self


class ClosureEvidence(StrictContract):
    """Shared normalized envelope produced by either runtime mode."""

    schema_version: Literal["itda.catalog-optional-media-closure-evidence.v1"] = (
        "itda.catalog-optional-media-closure-evidence.v1"
    )
    execution_mode: Literal["captured_replay", "fresh_collection"]
    closure_plan_sha256: Sha256
    frontier_sha256: Sha256
    universe_root_sha256: Sha256
    target_root_sha256: Sha256
    normalized_rows: Annotated[
        tuple[ClosureNormalizedEvidenceRow, ...],
        Field(min_length=1, max_length=60),
    ]
    normalized_rows_root_sha256: Sha256
    captured_evidence_root_sha256: Sha256 | None
    fresh_request_identity_sha256: Sha256 | None
    authority_receipt_sha256: Sha256 | None
    credential_reference_sha256: Sha256 | None
    attempts: tuple[ClosureAttemptReceipt, ...]
    provider_traffic_performed: Annotated[bool, Field(strict=True)]
    evidence_sha256: Sha256

    @model_validator(mode="after")
    def validate_evidence(self) -> Self:
        ids = tuple(row.place_entity_id for row in self.normalized_rows)
        if ids != tuple(sorted(ids)) or len(set(ids)) != len(ids):
            raise ValueError("closure evidence rows must use unique source-neutral order")
        expected_rows_root = canonical_sha256(
            [row.model_dump(mode="json") for row in self.normalized_rows]
        )
        if self.normalized_rows_root_sha256 != expected_rows_root:
            raise ValueError("closure normalized row root drifted")
        if self.execution_mode == "captured_replay":
            valid = (
                self.captured_evidence_root_sha256 is not None
                and self.fresh_request_identity_sha256 is None
                and self.authority_receipt_sha256 is None
                and self.credential_reference_sha256 is None
                and not self.attempts
                and not self.provider_traffic_performed
            )
        else:
            valid = (
                self.captured_evidence_root_sha256 is None
                and self.fresh_request_identity_sha256 is not None
                and self.authority_receipt_sha256 is not None
                and self.credential_reference_sha256 is not None
                and bool(self.attempts)
                and self.provider_traffic_performed
            )
        if not valid:
            raise ValueError("closure evidence contains mixed or forbidden mode fields")
        expected = canonical_sha256(self.model_dump(exclude={"evidence_sha256"}, mode="json"))
        if self.evidence_sha256 != expected:
            raise ValueError("closure evidence digest drifted")
        return self


__all__ = [
    "CLOSABLE_EVIDENCE_TYPES",
    "CLOSURE_EVIDENCE_SCHEMA_VERSION",
    "CLOSURE_PLAN_SCHEMA_VERSION",
    "CapturedEvidenceRoute",
    "ClosureAuthorityRequest",
    "ClosureAttemptReceipt",
    "ClosureEvidence",
    "ClosureEvidenceCoverage",
    "ClosureExecutionMode",
    "ClosureNormalizedEvidenceRow",
    "ClosurePlan",
    "ClosureTargetRow",
    "FreshCollectionBounds",
    "FreshCollectionRoute",
    "NonAddressableClosureTerminal",
]
