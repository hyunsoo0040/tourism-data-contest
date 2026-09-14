"""New destination inputs carry real identities, never invented legacy predictions."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from itda.contracts.grounded_source import (
    GroundedSourceProfile,
    GroundedSourceRelease,
    build_source_release,
    parse_grounded_input_release,
)
from itda.contracts.mvp_public_catalog import PublicPlaceCatalog, PublicPlaceRelations
from itda.domain.canonical import canonical_sha256
from itda.pipeline.grounded_assessment import build_assessment

NOW = datetime(2026, 9, 9, tzinfo=UTC)


def _catalog():
    rows = []
    for number, name, region, lat, lon in (
        (1, "서울 검증용 장소", "11110", 37.57, 126.98),
        (2, "제주 검증용 장소", "50110", 33.49, 126.53),
    ):
        row = {
            "place_id": "public:korea:" + str(number) * 64,
            "pool": "PUBLIC",
            "name_ko": name,
            "normalized_name_ko": name.replace(" ", ""),
            "category": "관광지",
            "administrative_area": "서울특별시 종로구" if number == 1 else "제주특별자치도 제주시",
            "region_code": region,
            "address_ko": name,
            "latitude": lat,
            "longitude": lon,
            "provider_crosswalk": [{"provider": "TOUR_API", "source_id": str(number)}],
            "evidence_ids": ["evidence:" + str(number) * 64],
            "duplicate_group_id": "duplicate:" + str(number) * 64,
        }
        rows.append(row | {"row_sha256": canonical_sha256(row)})
    payload = {
        "schema_version": "public-place-catalog.v1",
        "pool": "PUBLIC",
        "region": "전국",
        "places": rows,
        "evidence_inventory_sha256": "a" * 64,
        "blind_overlap_count": 0,
    }
    catalog = PublicPlaceCatalog.model_validate(
        payload | {"catalog_sha256": canonical_sha256(payload)}
    )
    relation_payload = {
        "schema_version": "public-place-relations.v1",
        "catalog_sha256": catalog.catalog_sha256,
        "catalog_place_ids": [row.place_id for row in catalog.places],
        "relations": [],
    }
    relations = PublicPlaceRelations.model_validate(
        relation_payload | {"relations_sha256": canonical_sha256(relation_payload)}
    )
    return catalog, relations


def test_fresh_source_release_is_reproducible_and_has_no_model_scores():
    catalog, relations = _catalog()
    release = build_source_release(catalog, relations, created_at=NOW)
    assert release == build_source_release(catalog, relations, created_at=NOW)
    assert release.published_count == 2
    assert parse_grounded_input_release(release.model_dump(mode="json")) == release
    assert isinstance(release, GroundedSourceRelease)
    assert all("scores" not in profile.model_dump() for profile in release.profiles)
    assert all(not hasattr(profile, "scores") for profile in release.profiles)


def test_source_identity_rejects_tampering_and_injected_predictions():
    catalog, relations = _catalog()
    release = build_source_release(catalog, relations, created_at=NOW)
    profile = release.profiles[0].model_dump(mode="json")
    with pytest.raises(ValidationError, match="source profile hash differs"):
        GroundedSourceProfile.model_validate(profile | {"place_name_ko": "다른 장소"})
    with pytest.raises(ValidationError, match="Extra inputs"):
        GroundedSourceProfile.model_validate(profile | {"scores": {"H": 0}})
    altered = release.model_dump(mode="json")
    altered["profiles"] = [altered["profiles"][0], altered["profiles"][0]]
    with pytest.raises(ValidationError, match="membership"):
        GroundedSourceRelease.model_validate(altered)


def test_missing_new_analysis_keeps_unknown_axes_without_fake_zero_baseline():
    catalog, relations = _catalog()
    profile = build_source_release(catalog, relations, created_at=NOW).profiles[0]
    result = build_assessment(
        profile=profile,
        judgments={},
        facts={},
        source_release_sha256="b" * 64,
        assessed_at=NOW,
    )
    assert result.raw_axes == {"H": None, "E": None, "R": None}
    assert result.axis_deltas == {"H": None, "E": None, "R": None}
    assert result.comparison_basis == "NO_INDEPENDENT_ANALYSIS"
    assert all(item.value is None for item in result.bundle.dimensions.values())


def test_fresh_batch_cli_builds_closed_source_candidate_and_resumes_without_legacy(tmp_path):
    from itda.cli.analyze_grounded_places import main
    from itda.contracts.grounded_release import GroundedReleaseCandidate
    from itda.pipeline.destination_evidence import (
        DestinationEvidenceSnapshot,
        atomic_json,
        canonical_place,
    )

    catalog, relations = _catalog()
    atomic_json(tmp_path / "catalog.json", catalog.model_dump(mode="json"))
    atomic_json(tmp_path / "relations.json", relations.model_dump(mode="json"))
    source_directory = tmp_path / "sources"
    for place in catalog.places:
        fields = {
            "schema_version": "destination-evidence.v1",
            "place": canonical_place(place).model_dump(mode="json"),
            "category": place.category,
            "catalog_row_sha256": place.row_sha256,
            "collected_at": NOW.isoformat().replace("+00:00", "Z"),
            "receipts": [],
            "raw_responses": [],
            "evidence": [],
            "text_lineage": [],
            "images": [],
            "coverage": {"semantic_evidence_version": "v2"},
        }
        snapshot = DestinationEvidenceSnapshot.model_validate(
            fields | {"snapshot_sha256": canonical_sha256(fields)}
        )
        atomic_json(
            source_directory / (place.place_id.rsplit(":", 1)[-1] + ".json"),
            snapshot.model_dump(mode="json"),
        )
    output = tmp_path / "batch"
    arguments = [
        "--catalog",
        str(tmp_path / "catalog.json"),
        "--relations",
        str(tmp_path / "relations.json"),
        "--reuse-sources",
        str(source_directory),
        "--output",
        str(output),
        "--cache",
        str(tmp_path / "cache"),
        "--offline",
        "--skip-mood",
        "--semantic-cache-version",
        "v2",
        "--workers",
        "40",
    ]
    assert main(arguments) == 0
    original = (output / "candidate.json").read_bytes()
    candidate = GroundedReleaseCandidate.model_validate_json(original)
    assert isinstance(candidate.raw_release, GroundedSourceRelease)
    assert len(candidate.assessments) == 2
    assert candidate.analysis_run["max_model_concurrency"] == 40
    assert all(
        observation.value is None
        for assessment in candidate.assessments
        for observation in assessment.dimensions.values()
    )
    assert main(arguments) == 0
    assert (output / "candidate.json").read_bytes() == original


def test_daily_quota_pause_does_not_stage_empty_candidate_and_keeps_source_only_resume(tmp_path):
    from types import SimpleNamespace

    from itda.pipeline.grounded_daily_refresh import run_grounded_daily
    from itda.pipeline.national_public_catalog import NationalProviderPaused

    catalog, relations = _catalog()
    release = build_source_release(catalog, relations, created_at=NOW)
    staged = []
    store = SimpleNamespace(load_active=lambda: None, stage=lambda value: staged.append(value))
    calls = []

    def paused_batch(**kwargs):
        calls.append(kwargs["raw_release"].release_sha256)
        raise NationalProviderPaused({"status": "PAUSED", "http_status": 429})

    arguments = dict(
        run_date=NOW.date(),
        root=tmp_path,
        catalog=catalog,
        store=store,
        cache=None,
        text_provider=SimpleNamespace(cache_version="v2"),
        mood_provider=None,
        raw_release_resolver=lambda: release,
        batch_runner=paused_batch,
        clock=lambda: NOW,
    )
    first = run_grounded_daily(**arguments)
    assert first.status == "PAUSED"
    assert first.reason == "PROVIDER_RATE_OR_QUOTA_LIMIT"
    assert first.candidate_sha256 is None
    assert not staged
    again = run_grounded_daily(**arguments)
    assert again.status == "PAUSED" and again.plan_sha256 == first.plan_sha256
    assert calls == [release.release_sha256, release.release_sha256]
    assert not staged
