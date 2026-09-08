"""Deterministic contracts for the Phase 2 official-provider transport seam."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from itda.contracts.base import Sha256, StableId, StrictContract, Version, require_utc
from itda.domain.canonical import canonical_sha256

ProviderOutcome = Literal[
    "SUCCESS",
    "NO_DATA",
    "RETRYABLE_FOR_RESUME",
    "TERMINAL_OPERATOR_ACTION",
]
TerminalState = Literal[
    "SUCCESS",
    "NO_DATA",
    "RETRYABLE_FOR_RESUME",
    "TERMINAL_OPERATOR_ACTION",
]

OFFICIAL_DATASETS: dict[str, dict[str, object]] = {
    "TOUR_API": {
        "official_dataset_id": "15101578",
        "host": "apis.data.go.kr",
        "service": "KorService2",
        "operations": (
            "areaBasedList2",
            "detailCommon2",
            "detailIntro2",
            "detailInfo2",
            "detailImage2",
        ),
    },
    "ODII": {
        "official_dataset_id": "15101971",
        "host": "apis.data.go.kr",
        "service": "Odii",
        "operations": ("themeSearchList", "themeBasedList", "storyBasedList"),
    },
    "TOURISM_PHOTO": {
        "official_dataset_id": "15101914",
        "host": "apis.data.go.kr",
        "service": "PhotoGalleryService1",
        "operations": ("list", "search", "detail", "sync"),
        "dataset_rights": "KOGL_TYPE_1_ATTRIBUTION",
    },
}

TOURAPI_CLASSIFICATION_FIELDS = (
    "lDongRegnCd",
    "lDongSignguCd",
    "lclsSystm1",
    "lclsSystm2",
    "lclsSystm3",
)

_RETRYABLE_CODES = frozenset({"02", "04", "05", "21", "22", "99"})
_OPERATOR_CODES = frozenset({"10", "11", "12", "20", "30", "31", "32", "33"})
_OPERATOR_RATIONALES = {
    "10": "invalid request parameters require operator correction",
    "11": "required request parameters are missing",
    "12": "the requested provider operation is unavailable",
    "20": "provider access is denied",
    "30": "the service key is unregistered",
    "31": "the service key is expired",
    "32": "the request originated from an unregistered IP",
    "33": "the request used an unsigned service key",
}
_SECRET_FRAGMENTS = (
    "servicekey",
    "api_key",
    "apikey",
    "token",
    "secret",
    "authorization",
)
MAX_COLLECTION_PAGES = 1_000
EXPECTED_PERMISSION_DATASET_IDS = ("15101578", "15101971", "15101914")


class CoverageSeedRow(StrictContract):
    seed_id: Annotated[str, Field(strict=True, pattern=r"^proposal:gyeongju:[0-9]{3}$")]
    proposal_order: Annotated[int, Field(strict=True, ge=1, le=36)]
    name_ko: Annotated[str, Field(strict=True, min_length=1, max_length=240)]
    hypothesis_group: Literal[
        "HISTORY_CULTURE",
        "HISTORY_SCENERY_BOUNDARY",
        "IMAGE_MODERN_CONTENT",
        "REST_WALK_IMMERSION",
    ]


class CoverageSeedManifest(StrictContract):
    schema_version: Literal["proposal-coverage-seed-v1"]
    source_attachment_name: Literal["pasted-text.txt"]
    source_attachment_sha256: Sha256
    rows: tuple[CoverageSeedRow, ...]
    seed_manifest_sha256: Sha256

    @model_validator(mode="after")
    def validate_exact_order_and_hash(self) -> Self:
        if len(self.rows) != 36:
            raise ValueError("coverage seed must contain exactly 36 rows")
        expected_ids = tuple(f"proposal:gyeongju:{index:03d}" for index in range(1, 37))
        if tuple(row.seed_id for row in self.rows) != expected_ids:
            raise ValueError("coverage seed IDs must preserve proposal order")
        if tuple(row.proposal_order for row in self.rows) != tuple(range(1, 37)):
            raise ValueError("coverage seed proposal_order must be contiguous")
        expected = canonical_sha256(self.model_dump(exclude={"seed_manifest_sha256"}, mode="json"))
        if self.seed_manifest_sha256 != expected:
            raise ValueError("seed_manifest_sha256 does not match canonical seed")
        return self


CoverageDispositionStatus = Literal[
    "LINKED",
    "MISSING_WITH_EVIDENCE",
    "EXCLUDED_WITH_EVIDENCE",
]


class SeedCoverageDisposition(StrictContract):
    seed_id: Annotated[str, Field(strict=True, pattern=r"^proposal:gyeongju:[0-9]{3}$")]
    status: CoverageDispositionStatus
    candidate_id: Annotated[str | None, Field(strict=True, min_length=1, max_length=200)]
    reason: Annotated[str, Field(strict=True, min_length=1, max_length=1_000)]
    evidence_sha256: tuple[Sha256, ...]

    @model_validator(mode="after")
    def validate_evidence_backed_state(self) -> Self:
        if not self.reason.strip():
            raise ValueError("coverage disposition reason must not be blank")
        if not self.evidence_sha256:
            raise ValueError("coverage disposition requires evidence")
        if len(set(self.evidence_sha256)) != len(self.evidence_sha256):
            raise ValueError("coverage disposition evidence must be unique")
        if self.status == "LINKED" and self.candidate_id is None:
            raise ValueError("LINKED disposition requires candidate_id")
        if self.status != "LINKED" and self.candidate_id is not None:
            raise ValueError("missing or excluded disposition cannot link a candidate")
        return self


class PermissionTermsProjection(StrictContract):
    commercial_use: Annotated[bool, Field(strict=True)]
    derivative_use: Annotated[bool, Field(strict=True)]
    attribution_required: Annotated[bool, Field(strict=True)]
    availability: Literal["AVAILABLE", "UNAVAILABLE"]
    explicit_restrictions: tuple[
        Annotated[str, Field(strict=True, min_length=1, max_length=500)], ...
    ] = ()

    @model_validator(mode="after")
    def unavailable_must_fail_closed(self) -> Self:
        if self.availability == "UNAVAILABLE" and (self.commercial_use or self.derivative_use):
            raise ValueError("unavailable permission evidence cannot grant usage")
        return self


class PermissionRequirement(StrictContract):
    provider: Literal["TOUR_API", "ODII", "TOURISM_PHOTO"]
    official_dataset_id: Annotated[str, Field(strict=True, pattern=r"^[0-9]{8}$")]
    official_url: Annotated[
        str,
        Field(
            strict=True,
            pattern=r"^https://www\.data\.go\.kr/data/[0-9]{8}/openapi\.do$",
        ),
    ]
    expected_terms: Literal[
        "PUBLIC_DATASET_TERMS_REVIEW_REQUIRED",
        "KOGL_TYPE_1_ATTRIBUTION",
    ]

    @model_validator(mode="after")
    def identity_must_match_provider(self) -> Self:
        dataset = OFFICIAL_DATASETS[self.provider]
        if self.official_dataset_id != dataset["official_dataset_id"]:
            raise ValueError("permission requirement dataset does not match provider")
        if self.official_url != (
            f"https://www.data.go.kr/data/{self.official_dataset_id}/openapi.do"
        ):
            raise ValueError("permission requirement URL does not match dataset")
        if (self.provider == "TOURISM_PHOTO") != (self.expected_terms == "KOGL_TYPE_1_ATTRIBUTION"):
            raise ValueError("PhotoGallery requires its independent Type-1 terms")
        return self


class PermissionPageSnapshot(StrictContract):
    schema_version: Literal["permission-page-snapshot-v1"]
    official_dataset_id: Annotated[str, Field(strict=True, pattern=r"^[0-9]{8}$")]
    official_url: Annotated[
        str,
        Field(
            strict=True,
            pattern=r"^https://www\.data\.go\.kr/data/[0-9]{8}/openapi\.do$",
        ),
    ]
    retrieved_at: datetime
    terms_projection: PermissionTermsProjection
    page_response_sha256: Sha256
    snapshot_sha256: Sha256

    @field_validator("retrieved_at")
    @classmethod
    def retrieved_at_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="retrieved_at")

    @model_validator(mode="after")
    def validate_dataset_url_and_hash(self) -> Self:
        if self.official_dataset_id not in EXPECTED_PERMISSION_DATASET_IDS:
            raise ValueError("permission snapshot dataset is outside the approved set")
        if self.official_url != (
            f"https://www.data.go.kr/data/{self.official_dataset_id}/openapi.do"
        ):
            raise ValueError("permission snapshot URL does not match dataset")
        expected = canonical_sha256(self.model_dump(exclude={"snapshot_sha256"}, mode="json"))
        if self.snapshot_sha256 != expected:
            raise ValueError("permission snapshot hash does not match canonical fields")
        return self


class PermissionEvidenceSet(StrictContract):
    snapshots: tuple[PermissionPageSnapshot, ...]
    permission_evidence_sha256: Sha256

    @classmethod
    def from_snapshots(cls, snapshots: Iterable[PermissionPageSnapshot]) -> PermissionEvidenceSet:
        frozen = tuple(snapshots)
        return cls(
            snapshots=frozen,
            permission_evidence_sha256=canonical_sha256(
                [snapshot.model_dump(mode="json") for snapshot in frozen]
            ),
        )

    @model_validator(mode="after")
    def validate_exact_order_and_hash(self) -> Self:
        if tuple(item.official_dataset_id for item in self.snapshots) != (
            EXPECTED_PERMISSION_DATASET_IDS
        ):
            raise ValueError("permission evidence must contain the exact canonical three datasets")
        expected = canonical_sha256(
            [snapshot.model_dump(mode="json") for snapshot in self.snapshots]
        )
        if self.permission_evidence_sha256 != expected:
            raise ValueError("permission evidence hash does not match snapshots")
        return self


class CredentialReference(StrictContract):
    provider_label: Literal["tourapi", "odii", "tourism-photo"]
    path: Literal[".secrets/itda-api.env", ".secrets/itda-odii.env"]
    variable_name: Literal["TOUR_API_SERVICE_KEY", "ODII_SERVICE_KEY"]
    reference: Annotated[str, Field(strict=True, min_length=1, max_length=300)]

    @model_validator(mode="after")
    def validate_exact_plan_binding(self) -> Self:
        expected = {
            "tourapi": (".secrets/itda-api.env", "TOUR_API_SERVICE_KEY"),
            "odii": (".secrets/itda-odii.env", "ODII_SERVICE_KEY"),
            "tourism-photo": (
                ".secrets/itda-api.env",
                "TOUR_API_SERVICE_KEY",
            ),
        }[self.provider_label]
        if (self.path, self.variable_name) != expected:
            raise ValueError("credential reference does not match the collection plan")
        if self.reference != f"{self.path}:{self.variable_name}":
            raise ValueError("credential reference rendering does not match path and name")
        return self


class CredentialPreflightResult(StrictContract):
    provider_label: Annotated[str, Field(strict=True, min_length=1, max_length=40)]
    reference: Annotated[str, Field(strict=True, min_length=1, max_length=300)]
    regular_file: Annotated[bool, Field(strict=True)]
    no_symlink: Annotated[bool, Field(strict=True)]
    owned_by_current_user: Annotated[bool, Field(strict=True)]
    mode_0600: Annotated[bool, Field(strict=True)]
    variable_name_present: Annotated[bool, Field(strict=True)]


class CatalogRequest(StrictContract):
    provider: Literal["TOUR_API", "ODII", "TOURISM_PHOTO"]
    official_dataset_id: Annotated[str, Field(strict=True, pattern=r"^[0-9]{8}$")]
    operation: Annotated[str, Field(strict=True, min_length=1, max_length=100)]
    transport_operation: Annotated[str, Field(strict=True, min_length=1, max_length=100)]
    scope: Literal["TINY", "BROAD"]
    secret_free_parameters: dict[
        Annotated[str, Field(strict=True, min_length=1, max_length=100)],
        Annotated[str, Field(strict=True, max_length=500)],
    ]
    page_ceiling: Annotated[int, Field(strict=True, ge=1, le=MAX_COLLECTION_PAGES)]
    per_attempt_timeout_seconds: Annotated[int, Field(strict=True, ge=1, le=300)]
    max_attempts: Annotated[int, Field(strict=True, ge=1, le=5)]
    initial_backoff_seconds: Annotated[float, Field(strict=True, ge=0, le=300)]
    max_backoff_seconds: Annotated[float, Field(strict=True, ge=0, le=300)]
    credential_reference: CredentialReference
    request_template_sha256: Sha256

    @field_validator("secret_free_parameters")
    @classmethod
    def parameters_must_be_secret_free(cls, value: dict[str, str]) -> dict[str, str]:
        if any(fragment in key.casefold() for key in value for fragment in _SECRET_FRAGMENTS):
            raise ValueError("catalog request parameters must exclude credentials")
        return value

    @model_validator(mode="after")
    def validate_provider_and_hash(self) -> Self:
        dataset = OFFICIAL_DATASETS[self.provider]
        if self.official_dataset_id != dataset["official_dataset_id"]:
            raise ValueError("catalog request dataset does not match provider")
        expected_labels = {
            "TOUR_API": "tourapi",
            "ODII": "odii",
            "TOURISM_PHOTO": "tourism-photo",
        }
        if self.credential_reference.provider_label != expected_labels[self.provider]:
            raise ValueError("catalog request credential provider does not match")
        expected = canonical_sha256(
            self.model_dump(exclude={"request_template_sha256"}, mode="json")
        )
        if self.request_template_sha256 != expected:
            raise ValueError("request template hash does not match canonical fields")
        return self


class CollectionPlan(StrictContract):
    collection_plan_version: Literal["catalog-v1"]
    collector_version: Literal["catalog-collector-v1"]
    schema_version: Literal["catalog-collection-v1"]
    seed_manifest_sha256: Sha256
    permission_requirements: tuple[PermissionRequirement, ...]
    permission_requirements_sha256: Sha256
    requests: tuple[CatalogRequest, ...]
    restricted_output_root: Literal["artifacts/restricted/catalog/v1/collection"]
    collection_plan_sha256: Sha256

    @model_validator(mode="after")
    def validate_exact_plan(self) -> Self:
        if (
            tuple(requirement.official_dataset_id for requirement in self.permission_requirements)
            != EXPECTED_PERMISSION_DATASET_IDS
        ):
            raise ValueError("collection plan requires the exact three permission pages")
        expected_permissions = canonical_sha256(
            [requirement.model_dump(mode="json") for requirement in self.permission_requirements]
        )
        if self.permission_requirements_sha256 != expected_permissions:
            raise ValueError("permission requirements hash does not match")
        if len(self.requests) != 6:
            raise ValueError("collection plan must contain three tiny then three broad requests")
        if tuple(item.scope for item in self.requests) != (
            "TINY",
            "TINY",
            "TINY",
            "BROAD",
            "BROAD",
            "BROAD",
        ):
            raise ValueError("collection plan scope order must be tiny then broad")
        expected_providers = (
            "TOUR_API",
            "ODII",
            "TOURISM_PHOTO",
            "TOUR_API",
            "ODII",
            "TOURISM_PHOTO",
        )
        if tuple(item.provider for item in self.requests) != expected_providers:
            raise ValueError("collection plan provider order is not canonical")
        expected = canonical_sha256(
            self.model_dump(exclude={"collection_plan_sha256"}, mode="json")
        )
        if self.collection_plan_sha256 != expected:
            raise ValueError("collection plan hash does not match canonical fields")
        return self


def classify_provider_result(provider_code: object) -> ProviderOutcome:
    """Normalize the documented provider code matrix without losing the raw code."""

    rendered = str(provider_code).strip()
    if rendered in {"00", "0000"}:
        return "SUCCESS"
    if rendered == "03":
        return "NO_DATA"
    if rendered in _RETRYABLE_CODES:
        return "RETRYABLE_FOR_RESUME"
    if rendered in _OPERATOR_CODES:
        return "TERMINAL_OPERATOR_ACTION"
    return "RETRYABLE_FOR_RESUME"


def provider_failure_rationale(provider_code: object) -> str:
    rendered = str(provider_code).strip()
    if rendered in _OPERATOR_RATIONALES:
        return _OPERATOR_RATIONALES[rendered]
    if rendered == "03":
        return "provider returned a valid no-data result"
    if rendered in _RETRYABLE_CODES:
        return "provider returned a transient result eligible for bounded resume"
    return "provider returned an unknown result eligible for bounded resume"


class RequestIdentity(StrictContract):
    provider: Annotated[str, Field(strict=True, min_length=1, max_length=40)]
    official_dataset_id: Annotated[str, Field(strict=True, pattern=r"^[0-9]{8}$")]
    operation: Annotated[str, Field(strict=True, min_length=1, max_length=100)]
    secret_free_parameters: dict[
        Annotated[str, Field(strict=True, min_length=1, max_length=100)],
        Annotated[str, Field(strict=True, max_length=500)],
    ]
    page: Annotated[int, Field(strict=True, ge=1, le=MAX_COLLECTION_PAGES)]
    collection_plan_version: Version
    collector_version: Version
    schema_version: Version
    plan_sha256: Sha256
    request_identity: Sha256

    @field_validator("secret_free_parameters")
    @classmethod
    def parameters_must_be_secret_free(cls, value: dict[str, str]) -> dict[str, str]:
        if any(fragment in key.casefold() for key in value for fragment in _SECRET_FRAGMENTS):
            raise ValueError("secret_free_parameters must exclude credential-bearing keys")
        return value

    @model_validator(mode="after")
    def provider_identity_must_match_allowlist(self) -> RequestIdentity:
        dataset = OFFICIAL_DATASETS.get(self.provider)
        if dataset is None:
            raise ValueError("provider is not an official Phase 2 dataset")
        if self.official_dataset_id != dataset["official_dataset_id"]:
            raise ValueError("official_dataset_id does not match provider")
        operations = dataset["operations"]
        assert isinstance(operations, tuple)
        if self.operation not in operations:
            raise ValueError("operation is not allowlisted for provider")
        expected = canonical_sha256(self.model_dump(exclude={"request_identity"}, mode="json"))
        if self.request_identity != expected:
            raise ValueError("request_identity does not match canonical request fields")
        return self


class CollectionAttempt(StrictContract):
    request_identity: Sha256
    attempt_number: Annotated[int, Field(strict=True, ge=1, le=5)]
    terminal_state: TerminalState
    http_status: Annotated[int | None, Field(strict=True, ge=100, le=599)] = None
    provider_result_code: Annotated[str | None, Field(strict=True, min_length=1, max_length=80)] = (
        None
    )
    provider_result_value: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=200)
    ] = None
    normalized_failure_reason: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=300)
    ] = None
    terminal_reason: Annotated[str | None, Field(strict=True, min_length=1, max_length=500)] = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    elapsed_ms: Annotated[int | None, Field(strict=True, ge=0, le=300_000)] = None
    retry_classification: (
        Literal[
            "DO_NOT_RETRY",
            "RETRY",
            "RETRYABLE_FOR_RESUME",
        ]
        | None
    ) = None
    raw_body_sha256: Sha256
    raw_body_retention: Literal[
        "IMMUTABLE",
        "IMMUTABLE_ATTEMPT_SNAPSHOT",
        "REDACTED_CREDENTIAL",
        "REDACTED_SECRET_REFLECTION",
    ]
    safe_headers: dict[
        Annotated[str, Field(strict=True, min_length=1, max_length=80)],
        Annotated[str, Field(strict=True, max_length=500)],
    ]

    @field_validator("safe_headers")
    @classmethod
    def headers_must_be_allowlisted(cls, value: dict[str, str]) -> dict[str, str]:
        allowed = {"content-type", "retry-after", "x-ratelimit-limit", "x-ratelimit-remaining"}
        if not set(value).issubset(allowed):
            raise ValueError("safe_headers contains a non-allowlisted header")
        return value

    @field_validator("started_at", "completed_at")
    @classmethod
    def attempt_times_must_be_utc(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return require_utc(value, field_name="attempt timestamp")

    @model_validator(mode="after")
    def failure_state_requires_reason(self) -> Self:
        if self.terminal_state != "SUCCESS" and not (
            self.normalized_failure_reason or self.terminal_reason
        ):
            raise ValueError("non-success attempt requires a detailed terminal reason")
        if (
            self.started_at is not None
            and self.completed_at is not None
            and self.completed_at < self.started_at
        ):
            raise ValueError("attempt completed_at cannot precede started_at")
        return self


class NormalizedCandidate(StrictContract):
    candidate_id: Annotated[
        str, Field(strict=True, pattern=r"^candidate:[a-z0-9-]+:[A-Za-z0-9._:-]+$")
    ]
    name_ko: Annotated[str, Field(strict=True, min_length=1, max_length=240)]
    gyeongju_evidence: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    provider: Literal["TOUR_API", "ODII", "TOURISM_PHOTO"]
    official_dataset_id: Annotated[str, Field(strict=True, pattern=r"^[0-9]{8}$")]
    provider_content_id: StableId
    request_identity: Sha256
    raw_response_sha256: Sha256
    permission_snapshot_sha256: Sha256

    @model_validator(mode="after")
    def provenance_must_match_dataset(self) -> Self:
        if self.official_dataset_id != OFFICIAL_DATASETS[self.provider]["official_dataset_id"]:
            raise ValueError("candidate dataset does not match provider")
        if self.provider_content_id in EXPECTED_PERMISSION_DATASET_IDS:
            raise ValueError(
                "provider content ID must come from a response, not a dataset identity"
            )
        return self


class SuccessfulSnapshotEvidence(StrictContract):
    request_identity: Sha256
    relative_path: Annotated[
        str,
        Field(
            strict=True,
            min_length=1,
            max_length=500,
            pattern=r"^[A-Za-z0-9._/-]+$",
        ),
    ]
    before_sha256: Sha256
    after_sha256: Sha256
    before_mtime_ns: Annotated[int, Field(strict=True, ge=0)]
    after_mtime_ns: Annotated[int, Field(strict=True, ge=0)]

    @model_validator(mode="after")
    def resume_must_preserve_success(self) -> Self:
        if self.before_sha256 != self.after_sha256:
            raise ValueError("resume changed successful snapshot bytes")
        if self.before_mtime_ns != self.after_mtime_ns:
            raise ValueError("resume changed successful snapshot mtime")
        return self


class CollectionReport(StrictContract):
    schema_version: Literal["catalog-collection-report-v1"]
    collection_plan_sha256: Sha256
    seed_manifest_sha256: Sha256
    permission_evidence: PermissionEvidenceSet
    request_identities: tuple[RequestIdentity, ...]
    attempts: tuple[CollectionAttempt, ...]
    candidates: tuple[NormalizedCandidate, ...]
    seed_dispositions: tuple[SeedCoverageDisposition, ...]
    resume_evidence: tuple[SuccessfulSnapshotEvidence, ...]
    generated_at: datetime
    report_sha256: Sha256

    @field_validator("generated_at")
    @classmethod
    def generated_at_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="generated_at")

    @model_validator(mode="after")
    def validate_report_shape_and_hash(self) -> Self:
        if len({item.candidate_id for item in self.candidates}) != len(self.candidates):
            raise ValueError("candidate IDs must be unique")
        expected_seed_ids = tuple(f"proposal:gyeongju:{index:03d}" for index in range(1, 37))
        if tuple(item.seed_id for item in self.seed_dispositions) != expected_seed_ids:
            raise ValueError("report must cover all 36 seed rows in order")
        expected = canonical_sha256(self.model_dump(exclude={"report_sha256"}, mode="json"))
        if self.report_sha256 != expected:
            raise ValueError("report hash does not match canonical fields")
        return self


class LiveReportValidation(StrictContract):
    schema_version: Literal["catalog-live-report-validation-v1"]
    report_sha256: Sha256
    collection_plan_sha256: Sha256
    required_dataset_ids: tuple[str, ...]
    terminal_plan_complete: Annotated[bool, Field(strict=True)]
    minimum_candidate_count: Annotated[int, Field(strict=True, ge=1)]
    actual_unique_candidate_count: Annotated[int, Field(strict=True, ge=0)]
    all_seed_dispositions_present: Annotated[bool, Field(strict=True)]
    detailed_failures_present: Annotated[bool, Field(strict=True)]
    resume_proof_valid: Annotated[bool, Field(strict=True)]
    valid: Annotated[bool, Field(strict=True)]

    @model_validator(mode="after")
    def valid_requires_every_gate(self) -> Self:
        gates = (
            self.required_dataset_ids == EXPECTED_PERMISSION_DATASET_IDS,
            self.terminal_plan_complete,
            self.actual_unique_candidate_count >= self.minimum_candidate_count,
            self.all_seed_dispositions_present,
            self.detailed_failures_present,
            self.resume_proof_valid,
        )
        if self.valid != all(gates):
            raise ValueError("validation result must equal all report gates")
        return self


def build_request_identity(
    *,
    provider: str,
    official_dataset_id: str,
    operation: str,
    secret_free_parameters: Mapping[str, object],
    page: int,
    collection_plan_version: str,
    collector_version: str,
    schema_version: str,
    plan_sha256: str,
) -> RequestIdentity:
    normalized_parameters: dict[str, str] = {}
    for key, value in secret_free_parameters.items():
        if not isinstance(key, str):
            raise ValueError("secret-free parameter names must be strings")
        if value is None:
            normalized_parameters[key] = ""
        elif type(value) in (str, int, float, bool):
            normalized_parameters[key] = str(value)
        else:
            raise ValueError("secret-free parameter values must be scalar")
    fields = {
        "provider": provider,
        "official_dataset_id": official_dataset_id,
        "operation": operation,
        "secret_free_parameters": normalized_parameters,
        "page": page,
        "collection_plan_version": collection_plan_version,
        "collector_version": collector_version,
        "schema_version": schema_version,
        "plan_sha256": plan_sha256,
    }
    return RequestIdentity.model_validate({**fields, "request_identity": canonical_sha256(fields)})


def select_resume_identities(
    identities: Iterable[RequestIdentity],
    attempts: Iterable[CollectionAttempt],
) -> tuple[RequestIdentity, ...]:
    """Select only missing or retryable-failed identities, preserving plan order."""

    latest: dict[str, CollectionAttempt] = {}
    for attempt in attempts:
        previous = latest.get(attempt.request_identity)
        if previous is None or attempt.attempt_number >= previous.attempt_number:
            latest[attempt.request_identity] = attempt
    selected: list[RequestIdentity] = []
    for identity in identities:
        latest_attempt = latest.get(identity.request_identity)
        if latest_attempt is None or latest_attempt.terminal_state == "RETRYABLE_FOR_RESUME":
            selected.append(identity)
    return tuple(selected)


__all__ = [
    "CatalogRequest",
    "CollectionAttempt",
    "CollectionPlan",
    "CollectionReport",
    "CoverageSeedManifest",
    "CoverageSeedRow",
    "CredentialPreflightResult",
    "CredentialReference",
    "EXPECTED_PERMISSION_DATASET_IDS",
    "LiveReportValidation",
    "MAX_COLLECTION_PAGES",
    "NormalizedCandidate",
    "OFFICIAL_DATASETS",
    "PermissionEvidenceSet",
    "PermissionPageSnapshot",
    "PermissionRequirement",
    "PermissionTermsProjection",
    "RequestIdentity",
    "SeedCoverageDisposition",
    "SuccessfulSnapshotEvidence",
    "TOURAPI_CLASSIFICATION_FIELDS",
    "build_request_identity",
    "classify_provider_result",
    "provider_failure_rationale",
    "select_resume_identities",
]
