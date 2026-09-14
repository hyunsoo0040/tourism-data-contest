"""Synthetic complete pairs exercise real PostgreSQL promotion authority only.

No fixture score/report is human accuracy evidence and no real active pair is used.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg.types.json import Jsonb
from sqlalchemy.exc import DBAPIError

from itda.contracts.grounded_promotion import (
    SOURCE_LANES,
    UI_CASES,
    GroundedPromotionGate,
    GroundedPromotionReport,
)
from itda.contracts.grounded_release import GroundedReleaseCandidate
from itda.contracts.grounded_run import GROUNDED_POLICY
from itda.contracts.source_assessment import AssessmentMember, AssessmentReleaseManifest
from itda.db.assessment_release import AssessmentReleaseRepository, GroundedReleaseInvalid
from itda.db.session import create_database_engine, create_session_factory
from itda.domain.canonical import canonical_sha256
from itda.pipeline.destination_evidence import DestinationEvidenceSnapshot
from itda.pipeline.destination_mood import analyze_destination_mood
from itda.pipeline.grounded_assessment import build_assessment
from itda.tourism.accessibility import CanonicalTourismPlace
from tests.contract.test_mvp_scored_release import release
from tests.integration.profile_release_test_support import ensure_daily_glm_refresh_roles
from tests.integration.test_recommendation_runs import _migrate

NOW = datetime(2026, 9, 9, tzinfo=UTC)


def _hashed(cls, fields, name):
    draft = cls.model_construct(**fields, **{name: "0" * 64})
    payload = draft.model_dump(mode="json", exclude={name})
    return cls.model_validate(payload | {name: canonical_sha256(payload)})


def candidate_fixture(tag=0):
    raw = release(80)
    created = NOW + timedelta(seconds=tag)
    sources = tuple(
        _hashed(
            DestinationEvidenceSnapshot,
            dict(
                place=CanonicalTourismPlace(
                    place_id=profile.place_id, name_ko="합성 장소" + str(i)
                ),
                category="관광지",
                catalog_row_sha256=canonical_sha256({"synthetic-place": i}),
                collected_at=created,
                receipts=(),
                raw_responses=(),
                evidence=(),
                text_lineage=(),
                images=(),
                coverage={"fixture": "SYNTHETIC_TEST_ONLY"},
            ),
            "snapshot_sha256",
        )
        for i, profile in enumerate(raw.profiles)
    )
    source_hashes = tuple(sorted(canonical_sha256(s.model_dump(mode="json")) for s in sources))
    source_release = canonical_sha256(
        {
            "policy_version": "source-bundle-v1",
            "raw_release_sha256": raw.release_sha256,
            "source_snapshot_sha256": source_hashes,
        }
    )
    assessments = tuple(
        build_assessment(
            profile=p,
            judgments={},
            facts={},
            source_release_sha256=source_release,
            assessed_at=created,
        ).bundle
        for p in raw.profiles
    )
    moods = tuple(
        analyze_destination_mood(
            place_id=p.place_id,
            raw_profile_sha256=p.profile_sha256,
            source_release_sha256=source_release,
            assets=(),
            provider=None,
            assessed_at=created,
        )
        for p in raw.profiles
    )
    members = [
        {
            "place_id": a.place_id,
            "raw_profile_sha256": a.raw_profile_sha256,
            "assessment_bundle_sha256": a.bundle_sha256,
        }
        for a in assessments
    ]
    manifest = _hashed(
        AssessmentReleaseManifest,
        dict(
            raw_release_sha256=raw.release_sha256,
            source_snapshot_sha256=source_hashes,
            source_release_sha256=source_release,
            members=tuple(AssessmentMember.model_validate(member) for member in members),
            assessment_set_sha256=canonical_sha256(
                {"source_release_sha256": source_release, "members": members}
            ),
            created_at=created,
        ),
        "manifest_sha256",
    )
    analysis = {
        "schema_version": "grounded-destination-batch.v1",
        "scope": "PUBLIC_COMPLETE",
        "model": "glm-5.3-flash",
        "raw_release_sha256": raw.release_sha256,
        "source_release_sha256": source_release,
        "manifest_sha256": manifest.manifest_sha256,
        "fixture_origin": "SYNTHETIC_TEST_ONLY",
        "members": [
            {
                "place_id": a.place_id,
                "raw_profile_sha256": a.raw_profile_sha256,
                "assessment_bundle_sha256": a.bundle_sha256,
                "mood_bundle_sha256": m.bundle_sha256,
            }
            for a, m in zip(assessments, moods, strict=True)
        ],
    }
    analysis["run_sha256"] = canonical_sha256(analysis)
    return _hashed(
        GroundedReleaseCandidate,
        dict(
            raw_release=raw,
            manifest=manifest,
            assessments=assessments,
            moods=moods,
            source_snapshots=tuple(s.model_dump(mode="json") for s in sources),
            analysis_run=analysis,
            created_at=created,
        ),
        "candidate_sha256",
    )


def report_fixtures(candidate, *, failed=False, config=GROUNDED_POLICY.sha256):
    ranked = [p.place_id for p in candidate.raw_release.profiles[:5]]
    violations = {
        "constraint": [],
        "unauthorized_claim": [],
        "replay": [],
        "schema_identity": [],
        "structural_regression": [],
    }
    common = {
        "scope": "DEV",
        "dev_manifest_sha256": "a" * 64,
        "model": "glm-5.3-flash",
        "prompt_sha256": "b" * 64,
        "aggregation_policy_sha256": "c" * 64,
        "human_relevance_status": "NOT_MEASURED",
    }
    source = common | {
        "rows": [
            dict(
                scenario_id="synthetic:scenario",
                lane=lane,
                preference_sha256="d" * 64,
                source_bundle_sha256=canonical_sha256({"lane": lane}),
                model_response_sha256=canonical_sha256({"fixture-model": lane}),
                ranking=ranked,
                eligible_count=80,
                purpose_eligible_count=80,
                supported_dimensions=0,
                possible_dimensions=1680,
                checked_constraints=5,
                checked_claims=0,
                violations=violations | {"constraint": ["synthetic:failure"]}
                if failed and lane == "combined"
                else violations,
            )
            for lane in SOURCE_LANES
        ]
    }
    axis = common | {
        "comparison": "FIXED_SOURCE_SUBORDINATES_MODEL_AND_USER",
        "rows": [
            dict(
                scenario_id="synthetic:scenario",
                preference_sha256="d" * 64,
                source_bundle_sha256="e" * 64,
                subordinate_judgments_sha256="f" * 64,
                model_response_sha256="1" * 64,
                raw_independent_ranking=ranked,
                aggregated_ranking=ranked,
                compared_places=80,
                supported_axes=0,
                possible_axes=240,
                raw_violations=violations,
                aggregated_violations=violations,
            )
        ],
    }
    ui = {
        "openapi_sha256": "2" * 64,
        "frontend_release_sha256": "3" * 64,
        "cases": [
            dict(
                case=name,
                executed=1,
                failures=[],
                artifact_sha256=[canonical_sha256({"synthetic-ui": name})],
            )
            for name in UI_CASES
        ],
    }
    return tuple(
        _hashed(
            GroundedPromotionReport,
            dict(
                kind=kind,
                candidate_sha256=candidate.candidate_sha256,
                config_sha256=config,
                completed_at=candidate.created_at + timedelta(seconds=10),
                result=result,
                outcome="FAIL" if failed and kind == "SOURCE_ABLATION" else "PASS",
                failure_count=1 if failed and kind == "SOURCE_ABLATION" else 0,
            ),
            "report_sha256",
        )
        for kind, result in (("SOURCE_ABLATION", source), ("AXIS_COMPARISON", axis), ("API_UI", ui))
    )


def gate_fixture(candidate, reports):
    by_kind = {r.kind: r for r in reports}
    return _hashed(
        GroundedPromotionGate,
        dict(
            candidate_sha256=candidate.candidate_sha256,
            config_sha256=reports[0].config_sha256,
            source_ablation_sha256=by_kind["SOURCE_ABLATION"].report_sha256,
            axis_comparison_sha256=by_kind["AXIS_COMPARISON"].report_sha256,
            api_ui_verification_sha256=by_kind["API_UI"].report_sha256,
            verified_at=candidate.created_at + timedelta(seconds=20),
            passed=True,
        ),
        "gate_sha256",
    )


@pytest.fixture(scope="module")
def stack(postgres_harness):
    _migrate(postgres_harness)
    fixed = ensure_daily_glm_refresh_roles(postgres_harness)
    info = conninfo_to_dict(postgres_harness.dsns["admin"])
    service_dsn = make_conninfo(
        **(info | {"user": fixed["service_role"], "password": fixed["service_password"]})
    )
    writer = create_database_engine(service_dsn)
    reader = create_database_engine(postgres_harness.dsns["runtime"])
    candidate = candidate_fixture()
    yield (
        AssessmentReleaseRepository(create_session_factory(writer)),
        AssessmentReleaseRepository(create_session_factory(reader)),
        candidate,
        service_dsn,
    )
    writer.dispose()
    reader.dispose()


def test_stage_is_immutable_and_does_not_activate(stack, postgres_harness):
    writer, reader, candidate, service = stack
    before = reader.load_active()
    assert writer.stage(candidate) == candidate.candidate_sha256
    assert writer.stage(candidate) == candidate.candidate_sha256
    assert reader.load_candidate(candidate.candidate_sha256) == candidate
    assert reader.load_active() == before
    altered = candidate.model_copy(update={"candidate_sha256": "f" * 64})
    with pytest.raises(ValueError):
        writer.stage(altered)
    with pytest.raises(DBAPIError):
        reader.stage(candidate)
    with psycopg.connect(service, autocommit=True) as connection:
        for statement in (
            "UPDATE app.grounded_release_candidates SET payload='{}'::jsonb",
            "DELETE FROM app.grounded_release_candidates",
            "UPDATE app.grounded_release_active SET generation=2",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                connection.execute(statement)
    with (
        postgres_harness.connect("admin", autocommit=True) as connection,
        pytest.raises(psycopg.errors.CheckViolation),
    ):
        connection.execute("UPDATE app.grounded_release_candidates SET payload='{}'::jsonb")


def test_actual_report_payloads_are_required_and_bad_verdicts_rejected(stack):
    writer, reader, _, service = stack
    candidate = candidate_fixture(100)
    writer.stage(candidate)
    before = reader.load_active()
    reports = report_fixtures(candidate)
    gate = gate_fixture(candidate, reports)
    with pytest.raises(GroundedReleaseInvalid, match="report is missing"):
        writer.promote(gate)
    with psycopg.connect(service, autocommit=True) as connection, pytest.raises(psycopg.Error):
        connection.execute(
            "SELECT app.promote_grounded_release_pair_v1(%s,NULL)",
            (Jsonb(gate.model_dump(mode="json")),),
        )
    broken = report_fixtures(candidate, failed=True)[0].model_dump(mode="json")
    broken.update(outcome="PASS", failure_count=0)
    broken["report_sha256"] = canonical_sha256(
        {k: v for k, v in broken.items() if k != "report_sha256"}
    )
    with pytest.raises(ValueError, match="measured violations"):
        GroundedPromotionReport.model_validate(broken)
    with (
        psycopg.connect(service, autocommit=True) as connection,
        pytest.raises(psycopg.errors.CheckViolation),
    ):
        connection.execute("SELECT app.store_grounded_promotion_report_v1(%s)", (Jsonb(broken),))
    assert reader.load_active() == before


def test_passing_reports_promote_atomically_and_failures_retain_previous_pair(stack):
    writer, reader, candidate, _ = stack
    writer.stage(candidate)
    reports = report_fixtures(candidate)
    for report in reports:
        assert writer.store_report(report) == report.report_sha256
    gate = gate_fixture(candidate, reports)
    before = reader.load_active()
    generation = writer.promote(
        gate, expected_active_sha256=before.candidate_sha256 if before else None
    )
    assert writer.promote(gate) == generation
    active = reader.load_active_record()
    assert active.candidate == candidate and active.gate == gate and active.generation == generation
    with pytest.raises(DBAPIError):
        reader.promote(gate)
    second = candidate_fixture(1)
    writer.stage(second)
    failed = report_fixtures(second, failed=True)
    for report in failed:
        writer.store_report(report)
    with pytest.raises(ValueError, match="outcome or timing"):
        writer.promote(
            gate_fixture(second, failed), expected_active_sha256=candidate.candidate_sha256
        )
    wrong = gate_fixture(second, reports)
    with pytest.raises(ValueError, match="outcome or timing"):
        writer.promote(wrong, expected_active_sha256=candidate.candidate_sha256)
    assert reader.load_active() == candidate


def test_concurrent_promotions_compare_and_swap_complete_pairs(stack):
    writer, reader, first, _ = stack
    writer.stage(first)
    first_reports = report_fixtures(first)
    for report in first_reports:
        writer.store_report(report)
    before = reader.load_active()
    base_generation = writer.promote(
        gate_fixture(first, first_reports),
        expected_active_sha256=before.candidate_sha256 if before else None,
    )
    candidates = (candidate_fixture(2), candidate_fixture(3))
    gates = []
    for candidate in candidates:
        writer.stage(candidate)
        reports = report_fixtures(candidate)
        for report in reports:
            writer.store_report(report)
        gates.append(gate_fixture(candidate, reports))

    def promote(gate):
        try:
            return writer.promote(gate, expected_active_sha256=first.candidate_sha256)
        except DBAPIError as error:
            return error.orig.sqlstate

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = tuple(pool.map(promote, gates))
    assert sorted(str(v) for v in outcomes) == sorted([str(base_generation + 1), "40001"])
    active = reader.load_active_record()
    assert active.generation == base_generation + 1
    assert active.candidate.candidate_sha256 in {
        candidate.candidate_sha256 for candidate in candidates
    }
    assert active.gate.candidate_sha256 == active.candidate.candidate_sha256
    assert reader.load_candidate(first.candidate_sha256) == first


@pytest.mark.parametrize(
    "damage", ["null_artifact", "missing_measurement", "missing_lane", "changed_user"]
)
def test_raw_sql_report_cannot_fabricate_execution_or_comparable_coverage(stack, damage):
    writer, reader, candidate, service = stack
    writer.stage(candidate)
    reports = report_fixtures(candidate)
    broken = (reports[2] if damage == "null_artifact" else reports[0]).model_dump(mode="json")
    if damage == "null_artifact":
        broken["result"]["cases"][0]["artifact_sha256"] = [None]
    elif damage == "missing_measurement":
        broken["result"]["rows"][0].pop("checked_constraints")
    elif damage == "missing_lane":
        broken["result"]["rows"].pop()
    else:
        broken["result"]["rows"][0]["preference_sha256"] = "9" * 64
    broken["report_sha256"] = canonical_sha256(
        {k: v for k, v in broken.items() if k != "report_sha256"}
    )
    with pytest.raises(ValueError):
        GroundedPromotionReport.model_validate(broken)
    before = reader.load_active()
    with psycopg.connect(service, autocommit=True) as connection, pytest.raises(psycopg.Error):
        connection.execute("SELECT app.store_grounded_promotion_report_v1(%s)", (Jsonb(broken),))
    assert reader.load_active() == before


def test_candidate_member_hash_tampering_and_wrong_config_are_rejected(stack):
    writer, reader, candidate, service = stack
    writer.stage(candidate)
    broken = candidate.model_dump(mode="json")
    broken["assessments"][0]["raw_profile_sha256"] = "f" * 64
    broken["candidate_sha256"] = canonical_sha256(
        {k: v for k, v in broken.items() if k != "candidate_sha256"}
    )
    with (
        psycopg.connect(service, autocommit=True) as connection,
        pytest.raises(psycopg.errors.CheckViolation),
    ):
        connection.execute("SELECT app.stage_grounded_release_candidate_v1(%s)", (Jsonb(broken),))
    wrong = report_fixtures(candidate, config="f" * 64)
    for report in wrong:
        writer.store_report(report)
    with pytest.raises(GroundedReleaseInvalid, match="server policy"):
        writer.promote(gate_fixture(candidate, wrong))
