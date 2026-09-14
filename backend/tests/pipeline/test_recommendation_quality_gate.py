import pytest

from itda.domain.canonical import canonical_sha256
from itda.pipeline.recommendation_quality_gate import assess_release_quality
from tests.pipeline.test_daily_public_input import _bundled_release
from tests.pipeline.test_daily_refresh import CATALOG

VERSIONS = dict(
    kernel_version="kernel-test",
    projection_version="projection-test",
    policy_version="facts-test",
    scenario_suite_sha256="4" * 64,
)


def report(release):
    fields = {
        "schema_version": "recommendation-quality-report.v1",
        "binding": {"release_sha256": release.release_sha256, **VERSIONS},
        "consistency": {
            "status": "pass",
            "checks": [{"name": "synthetic", "passed": True, "detail": "synthetic-only"}],
        },
        "human_relevance": {"status": "unavailable", "reason": "NO_GENUINE_RELEVANCE_JUDGMENTS"},
    }
    return {**fields, "report_sha256": canonical_sha256(fields)}


def test_gate_requires_exact_report_and_preserves_legacy_serialization() -> None:
    release = _bundled_release()
    before = release.model_dump(mode="json")
    missing = assess_release_quality(
        release, previous_release=release, catalog=CATALOG, report=None, **VERSIONS
    )
    assert missing.status == "reject"
    assert "QUALITY_REPORT_MISSING" in missing.reasons
    passed = assess_release_quality(
        release, previous_release=release, catalog=CATALOG, report=report(release), **VERSIONS
    )
    assert passed.status == "pass"
    assert release.model_dump(mode="json") == before


def test_gate_rejects_rehashed_stale_and_failed_reports() -> None:
    release = _bundled_release()
    for field in ("release_sha256", *VERSIONS):
        stale = report(release)
        stale["binding"][field] = "stale"
        stale["report_sha256"] = canonical_sha256(
            {k: v for k, v in stale.items() if k != "report_sha256"}
        )
        outcome = assess_release_quality(
            release, previous_release=release, catalog=CATALOG, report=stale, **VERSIONS
        )
        assert outcome.status == "reject"
        assert "QUALITY_REPORT_BINDING_MISMATCH" in outcome.reasons
    failed = report(release)
    failed["consistency"]["status"] = "fail"
    failed["report_sha256"] = canonical_sha256(
        {k: v for k, v in failed.items() if k != "report_sha256"}
    )
    outcome = assess_release_quality(
        release, previous_release=release, catalog=CATALOG, report=failed, **VERSIONS
    )
    assert "QUALITY_CONSISTENCY_FAILED" in outcome.reasons


def test_gate_rejects_forged_score_and_source_binding() -> None:
    release = _bundled_release()
    invalid = release.model_copy(
        update={
            "profiles": (
                release.profiles[0].model_copy(
                    update={
                        "scores": release.profiles[0].scores.model_copy(update={"H": float("nan")})
                    }
                ),
                *release.profiles[1:],
            )
        }
    )
    with pytest.warns(UserWarning, match="Pydantic serializer warnings"):
        outcome = assess_release_quality(
            invalid, previous_release=release, catalog=CATALOG, report=report(invalid), **VERSIONS
        )
    assert outcome.status == "reject"
    assert "QUALITY_RELEASE_INVALID" in outcome.reasons
    profile = release.profiles[0]
    foreign = profile.evidence_excerpts[0].evidence.model_copy(
        update={"provider_source_id": "foreign-source"}
    )
    profile = profile.model_copy(
        update={
            "evidence_excerpts": (
                profile.evidence_excerpts[0].model_copy(update={"evidence": foreign}),
            )
        }
    )
    invalid = release.model_copy(update={"profiles": (profile, *release.profiles[1:])})
    outcome = assess_release_quality(
        invalid, previous_release=release, catalog=CATALOG, report=report(invalid), **VERSIONS
    )
    assert outcome.status == "reject"


def test_drift_threshold_requires_review() -> None:
    release = _bundled_release()
    # Predecessor's score is lower; candidate is still the valid sealed release.
    profile = release.profiles[0]
    changed = profile.model_copy(
        update={
            "scores": profile.scores.model_copy(update={"H": 0 if profile.scores.H > 50 else 100})
        }
    )
    previous = release.model_copy(update={"profiles": (changed, *release.profiles[1:])})
    outcome = assess_release_quality(
        release,
        previous_release=previous,
        catalog=CATALOG,
        report=report(release),
        maximum_score_drift=40,
        **VERSIONS,
    )
    assert outcome.status == "review"
    assert "QUALITY_SCORE_DRIFT_REVIEW" in outcome.reasons
