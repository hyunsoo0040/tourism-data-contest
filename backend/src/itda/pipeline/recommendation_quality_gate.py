"""Fail-closed prepublication checks; a pass is not a human quality judgment."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from itda.contracts.mvp_daily_refresh import DailyScoredRelease, parse_daily_scored_release
from itda.contracts.mvp_public_catalog import PublicPlaceCatalog
from itda.contracts.mvp_scored_release import InformationState
from itda.domain.canonical import canonical_sha256
from itda.pipeline.mvp_place_scoring import justification_quotes_match
from itda.pipeline.place_facts import resolve_profile_conditions

QUALITY_GATE_VERSION = "recommendation-quality-gate.v1"
DEFAULT_MAXIMUM_SCORE_DRIFT = 40
_DRIFT_DIMENSIONS = ("H", "E", "R", "M1", "M2", "M3", "M4", "M5", "M6")


@dataclass(frozen=True, slots=True)
class ReleaseQualityDecision:
    status: Literal["pass", "review", "reject"]
    reasons: tuple[str, ...]
    release_sha256: str
    report_sha256: str | None
    maximum_observed_drift: int
    changed_place_ids: tuple[str, ...]
    supported_fact_count: int
    unknown_fact_count: int

    def as_dict(self) -> dict[str, object]:
        return {
            "gate_version": QUALITY_GATE_VERSION,
            "status": self.status,
            "reasons": list(self.reasons),
            "release_sha256": self.release_sha256,
            "report_sha256": self.report_sha256,
            "maximum_observed_drift": self.maximum_observed_drift,
            "changed_place_ids": list(self.changed_place_ids),
            "supported_fact_count": self.supported_fact_count,
            "unknown_fact_count": self.unknown_fact_count,
            "semantic_entailment": "NOT_HUMAN_REVIEWED",
        }


def assess_release_quality(
    release: DailyScoredRelease,
    *,
    previous_release: DailyScoredRelease,
    catalog: PublicPlaceCatalog,
    report: Mapping[str, object] | None,
    kernel_version: str,
    projection_version: str,
    policy_version: str,
    scenario_suite_sha256: str,
    maximum_score_drift: int = DEFAULT_MAXIMUM_SCORE_DRIFT,
) -> ReleaseQualityDecision:
    """Validate exact evaluated candidate, source bindings and configured drift.

    Old profiles are parsed with their original hashes. New profile quotations
    receive a structural existence check; neither path asserts human entailment.
    """
    if type(maximum_score_drift) is not int or not 0 <= maximum_score_drift <= 100:
        raise ValueError("quality drift threshold must be an integer from0to100")
    reasons: list[str] = []
    binding = {
        "release_sha256": release.release_sha256,
        "kernel_version": kernel_version,
        "projection_version": projection_version,
        "policy_version": policy_version,
        "scenario_suite_sha256": scenario_suite_sha256,
    }
    if report is None:
        reasons.append("QUALITY_REPORT_MISSING")
    else:
        try:
            expected_hash = canonical_sha256(
                {key: value for key, value in report.items() if key != "report_sha256"}
            )
            if (
                report.get("schema_version") != "recommendation-quality-report.v1"
                or report.get("report_sha256") != expected_hash
            ):
                reasons.append("QUALITY_REPORT_INVALID")
            if report.get("binding") != binding:
                reasons.append("QUALITY_REPORT_BINDING_MISMATCH")
            consistency = report.get("consistency")
            if not isinstance(consistency, Mapping):
                reasons.append("QUALITY_CONSISTENCY_FAILED")
            else:
                checks = consistency.get("checks")
                if (
                    consistency.get("status") != "pass"
                    or not isinstance(checks, (list, tuple))
                    or not checks
                    or any(
                        not isinstance(row, Mapping) or row.get("passed") is not True
                        for row in checks
                    )
                ):
                    reasons.append("QUALITY_CONSISTENCY_FAILED")
        except (TypeError, ValueError):
            reasons.append("QUALITY_REPORT_INVALID")
    try:
        # Revalidate through JSON fields: model_copy/model_construct must not bypass
        # nested score bounds, source hashes, partition or canonical release hashes.
        parse_daily_scored_release(release.model_dump(mode="json"))
    except (TypeError, ValueError):
        reasons.append("QUALITY_RELEASE_INVALID")

    prior = {row.place_id: row for row in previous_release.profiles}
    places = {row.place_id: row for row in catalog.places}
    changed: list[str] = []
    supported = unknown = maximum_drift = 0
    if "QUALITY_RELEASE_INVALID" not in reasons:
        for profile in release.profiles:
            previous = prior.get(profile.place_id)
            is_changed = previous is None or profile.profile_sha256 != previous.profile_sha256
            if is_changed:
                changed.append(profile.place_id)
                if not justification_quotes_match(
                    profile.scores,
                    {row.evidence_id: row.excerpt_ko for row in profile.evidence_excerpts},
                ):
                    reasons.append("QUALITY_QUOTE_BINDING_INVALID")
            place = places.get(profile.place_id)
            if place is None:
                reasons.append("QUALITY_PLACE_BINDING_INVALID")
                continue
            crosswalk: dict[str, tuple[str, ...]] = {}
            for row in place.provider_crosswalk:
                crosswalk[row.provider] = (*crosswalk.get(row.provider, ()), row.source_id)
            try:
                facts = resolve_profile_conditions(
                    profile, expected_provider_source_ids=crosswalk
                ).facts
                supported += sum(row.state == "FACT" for row in facts.observations.values())
                unknown += sum(row.state == "UNKNOWN" for row in facts.observations.values())
            except ValueError:
                reasons.append("QUALITY_SOURCE_BINDING_INVALID")
            if previous is not None:
                maximum_drift = max(
                    maximum_drift,
                    *(
                        abs(getattr(profile.scores, key) - getattr(previous.scores, key))
                        for key in _DRIFT_DIMENSIONS
                    ),
                )
        if not any(
            row.information_state != InformationState.AUDIT_ONLY for row in release.profiles
        ):
            reasons.append("QUALITY_NO_ELIGIBLE_CANDIDATES")
    status: Literal["pass", "review", "reject"] = "reject" if reasons else "pass"
    if maximum_drift > maximum_score_drift:
        reasons.append("QUALITY_SCORE_DRIFT_REVIEW")
        if status != "reject":
            status = "review"
    return ReleaseQualityDecision(
        status=status,
        reasons=tuple(sorted(set(reasons))),
        release_sha256=release.release_sha256,
        report_sha256=str(report["report_sha256"])
        if report and isinstance(report.get("report_sha256"), str)
        else None,
        maximum_observed_drift=maximum_drift,
        changed_place_ids=tuple(sorted(changed)),
        supported_fact_count=supported,
        unknown_fact_count=unknown,
    )
