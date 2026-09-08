"""Shared strict primitives for versioned IT-DA contracts."""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

Sha256 = Annotated[str, Field(strict=True, pattern=r"^[0-9a-f]{64}$")]
Version = Annotated[
    str,
    Field(strict=True, min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9._-]*$"),
]
StableId = Annotated[str, Field(strict=True, min_length=1, max_length=160)]
Score100 = Annotated[int, Field(strict=True, ge=0, le=100)]
BasisPoints = Annotated[int, Field(strict=True, ge=0, le=10_000)]
Confidence = Score100


class StrictContract(BaseModel):
    """Immutable contract base with no silent unknown-field acceptance."""

    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class ExperienceAxis(StrEnum):
    HISTORY_TRADITION = "HISTORY_TRADITION"
    EMOTION_IMAGE = "EMOTION_IMAGE"
    REST_IMMERSION = "REST_IMMERSION"


class DataSplit(StrEnum):
    PREVIEW = "PREVIEW"
    DEV = "DEV"
    BLIND = "BLIND"
    PUBLIC = "PUBLIC"
    SYNTHETIC = "SYNTHETIC"


class AssessmentStatus(StrEnum):
    SCORED = "SCORED"
    NOT_SCORED = "NOT_SCORED"


def require_utc(value: datetime, *, field_name: str) -> datetime:
    """Require an aware timestamp whose effective UTC offset is exactly zero."""

    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must use UTC offset +00:00")
    return value
