"""Current-path and active-identity guards cannot revive retired operational data."""

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from itda.api import dependencies
from itda.catalog_paths import (
    NATIONAL_CATALOG_PATH,
    NATIONAL_CURRENT_DIRECTORY,
    NATIONAL_EVIDENCE_PATH,
    NATIONAL_RELATIONS_PATH,
    is_national_candidate,
    is_national_catalog,
)
from itda.cli import initialize_grounded_release as initial
from itda.cli import run_daily_glm_refresh as daily
from itda.contracts.grounded_source import build_source_release
from itda.db.assessment_release import AssessmentReleaseRepository
from tests.integration.test_grounded_release_pairs import candidate_fixture as retired_candidate
from tests.integration.test_source_grounding_tracer import _synthetic_catalog
from tests.unit.test_grounded_source import _catalog


@pytest.fixture
def current():
    catalog, relations = _catalog()
    # This guard exercises validated source identity; analysis/ranking are tested separately.
    candidate = SimpleNamespace(
        raw_release=build_source_release(
            catalog, relations, created_at=datetime(2026, 9, 9, tzinfo=UTC)
        )
    )
    return catalog, candidate


def test_all_operational_defaults_share_national_current():
    assert (
        initial.DEFAULT_BUNDLE_DIRECTORY
        == NATIONAL_CURRENT_DIRECTORY
        == Path("artifacts/national/current")
    )
    assert NATIONAL_CATALOG_PATH == NATIONAL_CURRENT_DIRECTORY / "catalog.json"
    assert NATIONAL_EVIDENCE_PATH == NATIONAL_CURRENT_DIRECTORY / "evidence.json"
    assert NATIONAL_RELATIONS_PATH == NATIONAL_CURRENT_DIRECTORY / "relations.json"


@pytest.mark.parametrize("category", ["음식점", "숙박"])
def test_national_runtime_rejects_excluded_place_categories(current, category):
    catalog, _candidate = current
    mixed = catalog.model_copy(
        update={
            "places": (
                catalog.places[0].model_copy(update={"category": category}),
                *catalog.places[1:],
            )
        }
    )
    assert not is_national_catalog(mixed)


@pytest.mark.parametrize("explicit_retired", [False, True])
def test_missing_national_catalog_returns_503_without_reading_old_default_or_opening_db(
    tmp_path, monkeypatch, explicit_retired
):
    monkeypatch.chdir(tmp_path)
    old = Path("artifacts/public/catalog/public-place-catalog-v1.json")
    old.parent.mkdir(parents=True)
    old.write_text(_synthetic_catalog().model_dump_json())
    monkeypatch.delenv("ITDA_GROUNDED_CANDIDATE_SHA256", raising=False)
    monkeypatch.delenv("ITDA_PUBLIC_PLACE_CATALOG_PATH", raising=False)
    if explicit_retired:
        monkeypatch.setenv("ITDA_PUBLIC_PLACE_CATALOG_PATH", str(old))
    monkeypatch.setattr(
        dependencies,
        "create_database_engine",
        lambda *_: pytest.fail("database opened for retired/missing catalog"),
    )
    dependencies._recommendation_service_for_dsn.cache_clear()
    with pytest.raises(HTTPException) as error:
        dependencies._recommendation_service_for_dsn("synthetic-unused-dsn")
    assert error.value.status_code == 503
    assert error.value.detail["code"] == "NO_ACTIVE_SCORED_RELEASE"
    dependencies._recommendation_service_for_dsn.cache_clear()


def test_active_guard_requires_source_only_national_identity_and_current_catalog(current):
    catalog, candidate = current
    assert is_national_candidate(candidate, catalog)
    assert not is_national_candidate(retired_candidate(), catalog)
    changed = candidate.raw_release.model_copy(update={"catalog_sha256": "f" * 64})
    assert not is_national_candidate(SimpleNamespace(raw_release=changed), catalog)
    changed = candidate.raw_release.model_copy(update={"evidence_inventory_sha256": "f" * 64})
    assert not is_national_candidate(SimpleNamespace(raw_release=changed), catalog)


@pytest.mark.parametrize("active_kind", ["national", "retired", "missing", "different_catalog"])
def test_normal_api_resolver_serves_only_matching_national_active(
    tmp_path, monkeypatch, current, active_kind
):
    catalog, candidate = current
    if active_kind == "retired":
        candidate = retired_candidate()
    elif active_kind == "missing":
        candidate = None
    elif active_kind == "different_catalog":
        candidate = SimpleNamespace(
            raw_release=candidate.raw_release.model_copy(update={"catalog_sha256": "f" * 64})
        )
    catalog_path = tmp_path / "catalog.json"
    catalog_path.write_text(catalog.model_dump_json())
    monkeypatch.setenv("ITDA_PUBLIC_PLACE_CATALOG_PATH", str(catalog_path))
    monkeypatch.delenv("ITDA_GROUNDED_CANDIDATE_SHA256", raising=False)
    monkeypatch.setattr(dependencies, "create_database_engine", lambda *_: object())
    monkeypatch.setattr(dependencies, "create_session_factory", lambda *_: None)
    monkeypatch.setattr(dependencies, "_operating_information_service", lambda: None)
    monkeypatch.setattr(dependencies, "_source_grounding_service", lambda *_: None)
    monkeypatch.setattr(dependencies.ProductionTourismRegistry, "from_catalog", lambda *_: object())
    monkeypatch.setattr(AssessmentReleaseRepository, "load_active", lambda *_: candidate)
    dependencies._recommendation_service_for_dsn.cache_clear()
    service = dependencies._recommendation_service_for_dsn("synthetic-unused-dsn")
    assert service.candidate_resolver() is (candidate if active_kind == "national" else None)
    assert service.legacy._release_resolver() is None
    dependencies._recommendation_service_for_dsn.cache_clear()


@pytest.mark.parametrize("active_kind", ["national", "retired", "missing"])
def test_daily_store_filters_retired_active_before_batch_work(monkeypatch, current, active_kind):
    catalog, candidate = current
    if active_kind == "retired":
        candidate = retired_candidate()
    elif active_kind == "missing":
        candidate = None
    monkeypatch.setattr(AssessmentReleaseRepository, "load_active", lambda *_: candidate)
    store = daily._NationalDailyStore(None, catalog)
    assert store.load_active() is (candidate if active_kind == "national" else None)
