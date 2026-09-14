"""Real PostgreSQL upgrades and 1,000-member source-only staging, using synthetic evidence."""

from __future__ import annotations

from datetime import UTC, datetime

import psycopg
import pytest
from alembic import command
from psycopg.types.json import Jsonb
from sqlalchemy.exc import DBAPIError

from itda.contracts.grounded_release import GroundedReleaseCandidate
from itda.contracts.grounded_source import build_source_release
from itda.contracts.mvp_public_catalog import PublicPlace, PublicPlaceCatalog, PublicPlaceRelations
from itda.contracts.source_assessment import AssessmentMember, AssessmentReleaseManifest
from itda.db.assessment_release import AssessmentReleaseRepository
from itda.db.session import create_database_engine, create_session_factory
from itda.domain.canonical import canonical_sha256
from itda.pipeline.destination_evidence import DestinationEvidenceSnapshot, canonical_place
from itda.pipeline.destination_mood import analyze_destination_mood
from itda.pipeline.grounded_assessment import build_assessment
from tests.integration.test_daily_glm_refresh_migration import _config, _service_dsn
from tests.integration.test_grounded_release_pairs import _hashed, candidate_fixture
from tests.unit.test_grounded_source import _catalog

NOW = datetime(2026, 9, 9, tzinfo=UTC)


def national_candidate(count):
    template = _catalog()[0].places[0]
    places = []
    for number in range(count):
        digest = f"{number:064x}"
        payload = template.model_dump(mode="json", exclude={"row_sha256"})
        payload.update(
            place_id="public:korea:" + digest,
            name_ko=f"합성 장소 {number}",
            normalized_name_ko=f"합성장소{number}",
            duplicate_group_id="duplicate:" + digest,
        )
        places.append(payload | {"row_sha256": canonical_sha256(payload)})
    catalog = _hashed(
        PublicPlaceCatalog,
        {
            "schema_version": "public-place-catalog.v1",
            "pool": "PUBLIC",
            "region": "전국",
            "places": tuple(PublicPlace.model_validate(place) for place in places),
            "evidence_inventory_sha256": "a" * 64,
            "blind_overlap_count": None,
        },
        "catalog_sha256",
    )
    relations = _hashed(
        PublicPlaceRelations,
        {
            "schema_version": "public-place-relations.v1",
            "catalog_sha256": catalog.catalog_sha256,
            "catalog_place_ids": tuple(place.place_id for place in catalog.places),
            "relations": (),
        },
        "relations_sha256",
    )
    raw = build_source_release(catalog, relations, created_at=NOW)
    sources = tuple(
        _hashed(
            DestinationEvidenceSnapshot,
            {
                "place": canonical_place(place),
                "category": place.category,
                "catalog_row_sha256": place.row_sha256,
                "collected_at": NOW,
                "receipts": (),
                "raw_responses": (),
                "evidence": (),
                "text_lineage": (),
                "images": (),
                "coverage": {"fixture": "SYNTHETIC_TEST_ONLY"},
            },
            "snapshot_sha256",
        )
        for place in catalog.places
    )
    hashes = tuple(sorted(canonical_sha256(s.model_dump(mode="json")) for s in sources))
    source_release = canonical_sha256(
        {
            "policy_version": "source-bundle-v1",
            "raw_release_sha256": raw.release_sha256,
            "source_snapshot_sha256": hashes,
        }
    )
    assessments = tuple(
        build_assessment(
            profile=p, judgments={}, facts={}, source_release_sha256=source_release, assessed_at=NOW
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
            assessed_at=NOW,
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
        {
            "raw_release_sha256": raw.release_sha256,
            "source_snapshot_sha256": hashes,
            "source_release_sha256": source_release,
            "members": tuple(AssessmentMember.model_validate(row) for row in members),
            "assessment_set_sha256": canonical_sha256(
                {"source_release_sha256": source_release, "members": members}
            ),
            "created_at": NOW,
        },
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
        {
            "raw_release": raw,
            "manifest": manifest,
            "assessments": assessments,
            "moods": moods,
            "source_snapshots": tuple(s.model_dump(mode="json") for s in sources),
            "analysis_run": analysis,
            "created_at": NOW,
        },
        "candidate_sha256",
    )


def _rehash(payload):
    payload["candidate_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "candidate_sha256"}
    )
    return payload


def test_blank_and_existing_pg_upgrade_stages_1000_without_relaxing_legacy_or_authority(
    postgres_harness,
):
    config = _config(postgres_harness)
    service_dsn = _service_dsn(postgres_harness)
    command.upgrade(config, "head")
    writer_engine = create_database_engine(service_dsn)
    reader_engine = create_database_engine(postgres_harness.dsns["runtime"])
    writer = AssessmentReleaseRepository(create_session_factory(writer_engine))
    reader = AssessmentReleaseRepository(create_session_factory(reader_engine))
    try:
        fresh = national_candidate(1000)
        assert writer.stage(fresh) == fresh.candidate_sha256
        assert reader.load_candidate(fresh.candidate_sha256) == fresh
        assert reader.load_active() is None
        with pytest.raises(DBAPIError):
            reader.stage(fresh)
        with postgres_harness.connect("admin", autocommit=True) as connection:
            owner, security, grants = connection.execute(
                "SELECT pg_get_userbyid(proowner), prosecdef, proacl::text "
                "FROM pg_proc WHERE oid="
                "'app.stage_grounded_release_candidate_v1(jsonb)'::regprocedure"
            ).fetchone()
            assert owner == "itda_daily_glm_refresh_write_authority" and security
            assert "itda_daily_glm_refresh_service=X" in grants
        # Upgrade an existing populated database through the previous authority.
        command.downgrade(config, "0030_grounded_release_pairs")
        old = candidate_fixture()
        assert writer.stage(old) == old.candidate_sha256
        with (
            psycopg.connect(service_dsn, autocommit=True) as connection,
            pytest.raises(psycopg.errors.CheckViolation),
        ):
            connection.execute(
                "SELECT app.stage_grounded_release_candidate_v1(%s)",
                (Jsonb(fresh.model_dump(mode="json")),),
            )
        command.upgrade(config, "head")
        assert reader.load_candidate(old.candidate_sha256) == old
        assert writer.stage(fresh) == fresh.candidate_sha256
        assert reader.load_candidate(fresh.candidate_sha256) == fresh
        assert reader.load_active() is None
        # Direct SQL cannot smuggle incomplete members or relax legacy counts.
        with psycopg.connect(service_dsn, autocommit=True) as connection:
            invalid = fresh.model_dump(mode="json")
            invalid["raw_release"]["schema_version"] = "mvp-scored-release.v1"
            with pytest.raises(psycopg.errors.CheckViolation):
                connection.execute(
                    "SELECT app.stage_grounded_release_candidate_v1(%s)", (Jsonb(_rehash(invalid)),)
                )
            invalid = fresh.model_dump(mode="json")
            invalid["assessments"].pop()
            with pytest.raises(psycopg.errors.CheckViolation):
                connection.execute(
                    "SELECT app.stage_grounded_release_candidate_v1(%s)", (Jsonb(_rehash(invalid)),)
                )
            invalid = fresh.model_dump(mode="json")
            invalid["source_snapshots"][0]["catalog_row_sha256"] = "f" * 64
            with pytest.raises(psycopg.errors.CheckViolation):
                connection.execute(
                    "SELECT app.stage_grounded_release_candidate_v1(%s)", (Jsonb(_rehash(invalid)),)
                )
            invalid = fresh.model_dump(mode="json")
            invalid["raw_release"]["profiles"].append(invalid["raw_release"]["profiles"][0])
            with pytest.raises(psycopg.errors.CheckViolation):
                connection.execute(
                    "SELECT app.stage_grounded_release_candidate_v1(%s)", (Jsonb(_rehash(invalid)),)
                )
            assert (
                connection.execute(
                    "SELECT count(*) FROM app.grounded_release_candidates"
                ).fetchone()[0]
                == 2
            )
    finally:
        writer_engine.dispose()
        reader_engine.dispose()
