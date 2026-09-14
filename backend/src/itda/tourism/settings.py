"""Bounded external collection and freshness policy."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import date
from typing import Literal, Self

from pydantic import Field, model_validator

from itda.collectors.base import RequestPolicy
from itda.contracts.base import StrictContract


class TourismSettings(StrictContract):
    enabled: bool = True
    http_concurrency: int = Field(default=3, ge=1, le=5)
    timeout_seconds: float = Field(default=10.0, gt=0, le=30)
    max_attempts: int = Field(default=2, ge=1, le=3)
    positive_ttl_seconds: int = Field(default=86_400, ge=1, le=604_800)
    negative_ttl_seconds: int = Field(default=900, ge=1, le=3_600)
    discovery_max_pages: int = Field(default=5, ge=1, le=10)
    discovery_page_size: int = Field(default=100, ge=1, le=1_000)
    match_distance_meters: float = Field(default=150.0, gt=0, le=200)
    temporal_ttl_seconds: int = Field(default=21600, ge=1, le=86400)
    national_max_pages: int = Field(default=40, ge=1, le=100)
    national_page_size: int = Field(default=1000, ge=1, le=1000)
    max_context_places: int = Field(default=5, ge=1, le=5)
    max_walking_courses: int = Field(default=5, ge=1, le=5)
    max_related_suggestions: int = Field(default=3, ge=1, le=5)
    reference_lag_months: int = Field(default=2, ge=1, le=12)
    visitor_reference_start: date | None = None
    visitor_reference_end: date | None = None
    demand_reference_month: str | None = Field(default=None, pattern=r"^\d{4}(0[1-9]|1[0-2])$")
    related_reference_month: str | None = Field(default=None, pattern=r"^\d{4}(0[1-9]|1[0-2])$")
    model: Literal["glm-5.3-flash"] = "glm-5.3-flash"
    model_session_limit: int = Field(default=40, ge=1, le=40)
    batch_model_sessions: int = Field(default=32, ge=1, le=40)
    photo_model_sessions: int = Field(default=8, ge=1, le=40)

    @model_validator(mode="after")
    def validate_combined_bounds(self) -> Self:
        if self.batch_model_sessions + self.photo_model_sessions > self.model_session_limit:
            raise ValueError("batch and photo reservations exceed the shared model-session cap")
        if (self.visitor_reference_start is None) != (self.visitor_reference_end is None):
            raise ValueError("visitor reference period requires both dates")
        if (
            self.visitor_reference_start
            and self.visitor_reference_end
            and not 0 <= (self.visitor_reference_end - self.visitor_reference_start).days < 31
        ):
            raise ValueError("visitor reference period must be within31days")
        return self

    @classmethod
    def from_environment(cls, environment: Mapping[str, str]) -> TourismSettings:
        names = {
            "enabled": "ITDA_TOURISM_ENABLED",
            "http_concurrency": "ITDA_TOURISM_HTTP_CONCURRENCY",
            "timeout_seconds": "ITDA_TOURISM_TIMEOUT_SECONDS",
            "max_attempts": "ITDA_TOURISM_MAX_ATTEMPTS",
            "positive_ttl_seconds": "ITDA_TOURISM_FACILITY_TTL_SECONDS",
            "negative_ttl_seconds": "ITDA_TOURISM_NEGATIVE_TTL_SECONDS",
            "temporal_ttl_seconds": "ITDA_TOURISM_TEMPORAL_TTL_SECONDS",
            "national_max_pages": "ITDA_TOURISM_MAX_PAGES",
            "national_page_size": "ITDA_TOURISM_PAGE_SIZE",
            "reference_lag_months": "ITDA_TOURISM_REFERENCE_LAG_MONTHS",
            "visitor_reference_start": "ITDA_TOURISM_VISITOR_START",
            "visitor_reference_end": "ITDA_TOURISM_VISITOR_END",
            "demand_reference_month": "ITDA_TOURISM_DEMAND_MONTH",
            "related_reference_month": "ITDA_TOURISM_RELATED_MONTH",
            "model_session_limit": "ITDA_MODEL_SESSION_LIMIT",
            "batch_model_sessions": "ITDA_BATCH_MODEL_SESSIONS",
            "photo_model_sessions": "ITDA_PHOTO_MODEL_SESSIONS",
            "model": "ITDA_TOURISM_MODEL",
        }
        return cls.model_validate(
            {
                field: environment[name]
                for field, name in names.items()
                if environment.get(name, "").strip()
            }
        )

    def request_policy(self) -> RequestPolicy:
        return RequestPolicy(
            timeout_seconds=self.timeout_seconds,
            max_attempts=self.max_attempts,
            max_backoff_seconds=2.0,
        )
