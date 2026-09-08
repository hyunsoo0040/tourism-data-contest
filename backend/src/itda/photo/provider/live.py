"""Permanently inert live provider seam for Phase 6.

Phase 6 has no approval-authority implementation, so this module grants zero
external capability: no credential environment lookup, no endpoint, no HTTP
client, no transport, no DNS, no socket, no retry loop. Both the factory and
the analyze entrypoint run the offline gate and then an always-raising
unavailable-authority gate, so no code path can progress toward credential
resolution or client construction. Method signatures exist only so a future
approved phase can replace this class behind the same protocol.
"""

from __future__ import annotations

from typing import Final

from itda.photo.contracts import PhotoTraitCandidateSet
from itda.pipeline.offline_guard import require_live_collection_allowed

LIVE_ANALYSIS_UNAVAILABLE_REASON: Final[str] = "PHOTO_ANALYSIS_UNAVAILABLE"

__all__ = [
    "LIVE_ANALYSIS_UNAVAILABLE_REASON",
    "LivePhotoAnalysisProvider",
    "PhotoLiveAnalysisUnavailable",
    "require_unavailable_phase6_authority",
]


class PhotoLiveAnalysisUnavailable(RuntimeError):
    """Raised before any live capability exists in Phase 6."""

    def __init__(self, reason: str = LIVE_ANALYSIS_UNAVAILABLE_REASON) -> None:
        self.reason = reason
        super().__init__(f"photo live analysis unavailable: {reason}")


def require_unavailable_phase6_authority() -> None:
    """Always raise: Phase 6 has no live photo-analysis approval authority."""

    raise PhotoLiveAnalysisUnavailable(LIVE_ANALYSIS_UNAVAILABLE_REASON)


class LivePhotoAnalysisProvider:
    """Shape-compatible inert seam that can never reach a live provider."""

    def analyze(
        self,
        *,
        image_png: bytes,
        rubric_ko: str,
        job_id: str,
    ) -> PhotoTraitCandidateSet:
        del image_png, rubric_ko, job_id
        # Opt-in is true so the CI/no-network environment gates remain the only
        # refusal source here; the absent Phase 6 authority seam then refuses
        # every remaining environment before any capability stage.
        require_live_collection_allowed(explicit_opt_in=True)
        require_unavailable_phase6_authority()
        raise PhotoLiveAnalysisUnavailable(LIVE_ANALYSIS_UNAVAILABLE_REASON)  # pragma: no cover
