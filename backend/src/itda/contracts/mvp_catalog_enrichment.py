"""Strict contracts for bounded TourAPI PUBLIC catalog enrichment."""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StrictContract
from itda.contracts.mvp_public_catalog import VerifiedPermissionBinding
from itda.domain.canonical import canonical_sha256


class MvpCatalogEnrichmentRequest(StrictContract):
    provider: Literal["TOUR_API"]
    official_dataset_id: Literal["15101578"]
    operation: Literal["detailCommon2"]
    place_entity_id: Annotated[
        str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")
    ]
    provider_content_id: Annotated[
        str, Field(strict=True, min_length=1, max_length=160, pattern=r"^[A-Za-z0-9._:-]+$")
    ]
    source_row_sha256: Sha256


class MvpCatalogEnrichmentPlan(StrictContract):
    schema_version: Literal[
        "mvp-public-catalog-enrichment-plan.v3",
        "mvp-public-catalog-enrichment-plan.v4",
        "mvp-public-catalog-enrichment-plan.v5",
        "mvp-public-catalog-enrichment-plan.v6",
    ]
    parser_contract_version: Literal["provider-envelope.v1"] | None = None
    previous_attempt_result_sha256: Sha256 | None = None
    request_grammar_version: Literal["detail-common-fixed.v1"] | None = None
    successful_canary_result_sha256: Sha256 | None = None
    source_file_sha256: Sha256
    catalog_gap_report_sha256: Sha256
    description_ready_historical_count: Annotated[int, Field(strict=True, ge=0, le=99)]
    carried_success_count: Annotated[int, Field(strict=True, ge=0, le=100)] | None = None
    description_success_required: Annotated[int, Field(strict=True, ge=1, le=100)]
    strict_rights_state: Literal["PERMISSION_METADATA_VERIFIED"]
    permission_bindings: Annotated[
        tuple[VerifiedPermissionBinding, ...], Field(min_length=2, max_length=2)
    ]
    spare_count: Annotated[int, Field(strict=True, ge=0, le=20)]
    max_requests: Annotated[int, Field(strict=True, ge=1, le=80)]
    concurrency: Literal[1]
    timeout_seconds: Literal[15]
    response_body_max_bytes: Literal[262144]
    traffic_scope: Literal["TOURAPI_PUBLIC_CATALOG_COLLECTION_ONLY"]
    requests: Annotated[tuple[MvpCatalogEnrichmentRequest, ...], Field(min_length=1, max_length=80)]
    plan_sha256: Sha256

    @model_validator(mode="after")
    def validate_plan(self) -> Self:
        parser_lineage = (
            self.parser_contract_version,
            self.previous_attempt_result_sha256,
        )
        grammar_lineage = (
            self.request_grammar_version,
            self.successful_canary_result_sha256,
        )
        if self.schema_version.endswith(".v3") and any((*parser_lineage, *grammar_lineage)):
            raise ValueError("v3 plan cannot declare retry lineage")
        if self.schema_version.endswith(".v4") and (
            not all(parser_lineage) or any(grammar_lineage)
        ):
            raise ValueError("v4 plan requires parser-only retry lineage")
        if self.schema_version.endswith((".v5", ".v6")) and not all(
            (*parser_lineage, *grammar_lineage)
        ):
            raise ValueError("v5+ plan requires parser and fixed-grammar lineage")
        if self.schema_version.endswith(".v6"):
            if self.description_ready_historical_count != 0 or self.carried_success_count != 77:
                raise ValueError(
                    "v6 plan requires 77 verified v5 successes and no historical bodies"
                )
        elif self.carried_success_count is not None:
            raise ValueError("pre-v6 plan cannot declare carried successes")
        if tuple(row.official_dataset_id for row in self.permission_bindings) != (
            "15101578",
            "15101971",
        ):
            raise ValueError("enrichment plan requires exact permission bindings")
        usable_count = self.description_ready_historical_count + (self.carried_success_count or 0)
        if self.description_success_required != 100 - usable_count:
            raise ValueError("description success count is not derived from usable descriptions")
        if self.max_requests != len(self.requests):
            raise ValueError("max requests must equal the planned request count")
        if self.max_requests != min(80, self.description_success_required + self.spare_count):
            raise ValueError("request count must equal the bounded gap plus spare")
        keys = tuple((row.place_entity_id, row.provider_content_id) for row in self.requests)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("enrichment requests must use unique canonical order")
        if len({row.provider_content_id for row in self.requests}) != len(self.requests):
            raise ValueError("provider content IDs must be unique")
        excluded = {"plan_sha256"}
        if not self.schema_version.endswith(".v6"):
            excluded.add("carried_success_count")
        expected = canonical_sha256(
            self.model_dump(
                exclude=excluded,
                exclude_none=not self.schema_version.endswith((".v5", ".v6")),
                mode="json",
            )
        )
        if self.plan_sha256 != expected:
            raise ValueError("enrichment plan hash does not match")
        return self


class MvpCatalogEnrichmentOutcome(StrictContract):
    place_entity_id: Annotated[
        str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")
    ]
    provider_content_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    status: Literal["SUCCESS", "EMPTY", "FAILED"]
    reason: Literal[
        "DESCRIPTION_COLLECTED",
        "DESCRIPTION_EMPTY",
        "CONTENT_ID_MISMATCH",
        "MALFORMED_RESPONSE",
        "PROVIDER_REJECTED",
        "RESPONSE_BODY_LIMIT",
        "TRANSPORT_FAILURE",
    ]
    raw_response_sha256: Sha256 | None = None
    raw_response_file: Annotated[
        str,
        Field(strict=True, pattern=r"^responses/[A-Za-z0-9._:-]+-[0-9a-f]{64}\.json$"),
    ] | None = None
    overview: Annotated[str, Field(strict=True, min_length=1, max_length=4000)] | None = None
    name_ko: Annotated[str, Field(strict=True, min_length=1, max_length=240)] | None = None
    address_ko: Annotated[str, Field(strict=True, min_length=1, max_length=500)] | None = None
    latitude: Annotated[float, Field(strict=True, ge=35.0, le=36.5)] | None = None
    longitude: Annotated[float, Field(strict=True, ge=128.0, le=130.5)] | None = None

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        if self.status == "SUCCESS":
            if self.reason != "DESCRIPTION_COLLECTED" or not all(
                (self.raw_response_sha256, self.raw_response_file, self.overview)
            ):
                raise ValueError("successful enrichment requires response lineage and overview")
            if (self.latitude is None) != (self.longitude is None):
                raise ValueError("coordinates must be present as a pair")
        elif any(
            (
                self.raw_response_sha256,
                self.raw_response_file,
                self.overview,
                self.name_ko,
                self.address_ko,
                self.latitude,
                self.longitude,
            )
        ):
            raise ValueError("unsuccessful enrichment must not publish response details")
        return self


CanaryOutcome = Literal[
    "SUCCESS",
    "NO_DATA",
    "RETRYABLE_FOR_RESUME",
    "TERMINAL_OPERATOR_ACTION",
    "MISSING_RESULT_CODE",
    "MALFORMED_RESPONSE",
    "RESPONSE_BODY_LIMIT",
    "TRANSPORT_FAILURE",
]


class TourApiDiagnosticCanaryPlan(StrictContract):
    schema_version: Literal[
        "tourapi-diagnostic-canary-plan.v1",
        "tourapi-diagnostic-canary-plan.v2",
    ]
    enrichment_plan_sha256: Sha256
    enrichment_result_sha256: Sha256
    parser_contract_version: Literal["provider-envelope.v1"]
    request_grammar_version: Literal["detail-common-fixed.v1"] | None = None
    previous_canary_result_sha256: Sha256 | None = None
    endpoint: Literal[
        "https://apis.data.go.kr/B551011/KorService2/detailCommon2"
    ]
    request: MvpCatalogEnrichmentRequest
    max_requests: Literal[1]
    concurrency: Literal[1]
    timeout_seconds: Literal[15]
    response_body_max_bytes: Literal[262144]
    traffic_scope: Literal["TOURAPI_PROVIDER_RESULT_DIAGNOSTIC_ONLY"]
    plan_sha256: Sha256

    @model_validator(mode="after")
    def validate_plan_hash(self) -> Self:
        grammar_lineage = (
            self.request_grammar_version,
            self.previous_canary_result_sha256,
        )
        if self.schema_version.endswith(".v1") and any(grammar_lineage):
            raise ValueError("v1 canary cannot declare corrected grammar lineage")
        if self.schema_version.endswith(".v2") and not all(grammar_lineage):
            raise ValueError("v2 canary requires corrected grammar lineage")
        expected = canonical_sha256(
            self.model_dump(
                exclude={"plan_sha256"},
                exclude_none=self.schema_version.endswith(".v1"),
                mode="json",
            )
        )
        if self.plan_sha256 != expected:
            raise ValueError("diagnostic canary plan hash does not match")
        return self


class TourApiDiagnosticCanaryResult(StrictContract):
    schema_version: Literal["tourapi-diagnostic-canary-result.v1"]
    plan_sha256: Sha256
    attempted_count: Literal[1]
    provider_result_code: Annotated[
        str | None,
        Field(strict=True, pattern=r"^[0-9]{2,4}$"),
    ] = None
    normalized_outcome: CanaryOutcome
    raw_response_persisted: Literal[False]
    result_sha256: Sha256

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if self.normalized_outcome in {
            "SUCCESS",
            "NO_DATA",
            "RETRYABLE_FOR_RESUME",
            "TERMINAL_OPERATOR_ACTION",
        } and self.provider_result_code is None:
            raise ValueError("classified provider outcome requires numeric result code")
        if self.normalized_outcome in {
            "MISSING_RESULT_CODE",
            "MALFORMED_RESPONSE",
            "RESPONSE_BODY_LIMIT",
            "TRANSPORT_FAILURE",
        } and self.provider_result_code is not None:
            raise ValueError("local canary failure cannot publish a provider result code")
        expected = canonical_sha256(self.model_dump(exclude={"result_sha256"}, mode="json"))
        if self.result_sha256 != expected:
            raise ValueError("diagnostic canary result hash does not match")
        return self


class MvpCatalogEnrichmentResult(StrictContract):
    schema_version: Literal["mvp-public-catalog-enrichment-result.v3"]
    plan_sha256: Sha256
    catalog_gap_report_sha256: Sha256
    attempted_count: Annotated[int, Field(strict=True, ge=0, le=80)]
    successful_count: Annotated[int, Field(strict=True, ge=0, le=80)]
    description_gap_remaining: Annotated[int, Field(strict=True, ge=0, le=100)]
    strict_rights_state: Literal["PERMISSION_METADATA_VERIFIED"]
    permission_bindings: Annotated[
        tuple[VerifiedPermissionBinding, ...], Field(min_length=2, max_length=2)
    ]
    catalog_ready: Literal[False]
    public_artifact_written: Literal[False]
    outcomes: Annotated[tuple[MvpCatalogEnrichmentOutcome, ...], Field(max_length=80)]
    result_sha256: Sha256

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if tuple(row.official_dataset_id for row in self.permission_bindings) != (
            "15101578",
            "15101971",
        ):
            raise ValueError("enrichment result requires exact permission bindings")
        if self.attempted_count != len(self.outcomes):
            raise ValueError("attempt count does not match outcomes")
        if self.successful_count != sum(row.status == "SUCCESS" for row in self.outcomes):
            raise ValueError("success count does not match outcomes")
        expected = canonical_sha256(self.model_dump(exclude={"result_sha256"}, mode="json"))
        if self.result_sha256 != expected:
            raise ValueError("enrichment result hash does not match")
        return self
