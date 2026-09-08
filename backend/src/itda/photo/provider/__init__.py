"""Provider package: capability gates and the Phase 6 provider surface.

The live seam is permanently inert in Phase 6 — no approval authority
implementation exists, so every live request fails closed before any
credential, client, DNS, socket, or send capability can appear.
"""

from __future__ import annotations

from itda.photo.contracts import (
    PhotoAnalysisError,
    PhotoAnalysisProvider,
    PhotoConfirmedTrait,
    PhotoConsentNotice,
    PhotoJobPublicState,
    PhotoJobStateLiteral,
    PhotoJobStatus,
    PhotoPublicReason,
    PhotoTraitCandidate,
    PhotoTraitCandidateSet,
)
from itda.photo.provider.live import (
    LivePhotoAnalysisProvider,
    PhotoLiveAnalysisUnavailable,
)
from itda.photo.provider.synthetic import (
    SYNTHETIC_PHOTO_ANALYZER_ID,
    SyntheticPhotoAnalysisProvider,
)

PHOTO_PROVIDER_GATE_ORDER = (
    "authentication_ownership",
    "consent",
    "offline_guard",
    "phase_authority_unavailable",
    "durable_prepared_marker",
    "credential_resolution",
    "client_construction",
    "send_boundary",
)

__all__ = [
    "LIVE_ANALYSIS_UNAVAILABLE_REASON",
    "PHOTO_PROVIDER_GATE_ORDER",
    "SYNTHETIC_PHOTO_ANALYZER_ID",
    "LivePhotoAnalysisProvider",
    "PhotoAnalysisError",
    "PhotoAnalysisProvider",
    "PhotoConsentNotice",
    "PhotoConfirmedTrait",
    "PhotoJobPublicState",
    "PhotoJobStateLiteral",
    "PhotoJobStatus",
    "PhotoLiveAnalysisUnavailable",
    "PhotoPublicReason",
    "PhotoTraitCandidate",
    "PhotoTraitCandidateSet",
    "SyntheticPhotoAnalysisProvider",
]
