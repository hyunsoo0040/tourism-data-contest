from __future__ import annotations

import pytest

from itda.analysis.grounded_ablation import (
    measure_constraints,
    pair_identical_requests,
    rank_raw_axis_audit,
)
from itda.domain.grounded_recommendation import GroundedRecommendationError
from tests.unit.test_grounded_recommendation import candidate, preference, run


def test_sightseeing_preregistration_excludes_food_and_lodging_and_is_immutable(tmp_path):
    """Historical data exercises protocol code only; no new evaluation is claimed."""
    import json
    from pathlib import Path

    from itda.analysis.grounded_ablation import preregister
    from itda.contracts.grounded_release import GroundedReleaseCandidate

    root = Path(__file__).resolve().parents[3]
    fixture = root / "fixtures/historical-gyeongju/catalog/grounded-bootstrap/candidate.json"
    release = GroundedReleaseCandidate.model_validate_json(fixture.read_bytes())
    reference = next(image.candidate_set for mood in release.moods for image in mood.images)
    manifest = preregister(
        release, reference, tmp_path, scope="sightseeing", cache_version="v2", workers=40
    )
    assert len(manifest["members"]) == 24
    assert {member["purpose"] for member in manifest["members"]} == {"SIGHTSEEING"}
    methods = json.loads((tmp_path / "methods.json").read_text())
    scenarios = json.loads((tmp_path / "scenarios.json").read_text())
    assert methods["schema_version"] == "grounded-dev-sightseeing-ablation-v2"
    assert methods["scenario_count"] == len(scenarios) == 3
    assert {scenario["purpose"] for scenario in scenarios} == {"SIGHTSEEING"}
    assert methods["ndcg"] == "NOT_MEASURED_NO_GENUINE_HUMAN_JUDGMENTS"
    with pytest.raises(ValueError, match="preregistered evaluation artifact changed"):
        preregister(release, reference, tmp_path, scope="all", cache_version="v2", workers=40)


def test_raw_axis_audit_matches_shipped_kernel_when_axes_are_identical():
    candidates = tuple(
        candidate(i, axes="ER" if i % 3 == 0 else "HER", level=i % 5) for i in range(8)
    )
    pref = preference(axis_targets={"H": 80, "E": 55, "R": 35})
    raw = {c.place_id: {a: c.assessment.dimensions[a].value for a in "HER"} for c in candidates}
    pairs = ((candidates[0].place_id, candidates[1].place_id),)
    ranked = run(candidates, pairs=pairs, pref=pref)
    audited = rank_raw_axis_audit(candidates, pref, raw, pairs)
    assert audited["ranking"] == [i.place_id for i in ranked.items]
    assert [r["fit_score"] for r in audited["scores"]] == [i.fit_score for i in ranked.items]
    assert [r["rerank_score"] for r in audited["scores"]] == [
        i.contribution.rerank_score for i in ranked.items
    ]


def test_insufficient_source_lane_does_not_manufacture_five():
    candidates = tuple(candidate(i, axes="H") for i in range(8))
    with pytest.raises(GroundedRecommendationError):
        rank_raw_axis_audit(candidates, preference(), {}, ())


def test_measurement_retains_real_offending_cases():
    candidates = tuple(candidate(i) for i in range(6))
    ids = tuple(c.place_id for c in candidates[:5])
    pairs = ((ids[0], ids[1]),)
    violations, checked = measure_constraints(ids, candidates, preference(), pairs)
    assert checked > 0 and any("CANNOT_COAPPEAR" in v for v in violations)
    violations, _ = measure_constraints((ids[0],) * 5, candidates, preference(), ())
    assert any("DUPLICATE" in v for v in violations)


def test_identical_core_requests_use_earliest_valid_response_even_after_lane_retry_race(tmp_path):
    import json
    from types import SimpleNamespace

    c = candidate(1)
    pid = c.place_id
    request_sha = "a" * 64
    cache = tmp_path / "cache"
    for number, stamp in [(1, "2026-09-09T00:02:00+00:00"), (2, "2026-09-09T00:01:00+00:00")]:
        path = cache / f"attempt-{number}" / (request_sha + ".json")
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"retrieved_at": stamp}))

    class Provider:
        calls = []

        def analyze(self, source, *, cache_directory, live):
            assert live is False
            self.calls.append(str(cache_directory))
            return (
                SimpleNamespace(independent_axes={"H": 50, "E": 50, "R": 50}),
                {k: v for k, v in c.assessment.dimensions.items() if k not in "HER"},
                {
                    "validation_status": "VALIDATED",
                    "response_sha256": cache_directory.name[-1] * 64,
                },
            )

    source = SimpleNamespace(evidence=())
    initial = {
        "baseline": {
            pid: {
                "request_sha256": request_sha,
                "response_sha256": None,
                "model_status": "UNAVAILABLE",
            }
        },
        "images": {
            pid: {
                "request_sha256": request_sha,
                "response_sha256": "1" * 64,
                "model_status": "VALIDATED",
            }
        },
    }
    paired = pair_identical_requests(
        analyzed=initial,
        sources={lane: {pid: source} for lane in initial},
        profiles={pid: c.profile},
        lane_hashes={lane: "b" * 64 for lane in initial},
        provider=Provider(),
        cache_directory=cache,
        output=tmp_path / "results",
    )
    assert (
        paired["baseline"][pid]["response_sha256"]
        == paired["images"][pid]["response_sha256"]
        == "2" * 64
    )
    assert paired["baseline"][pid]["preliminary_status"] == "UNAVAILABLE"
    assert initial["baseline"][pid]["response_sha256"] is None
