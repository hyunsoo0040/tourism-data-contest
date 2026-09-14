"""Disposable DB only: public pin, idempotence, unexpected-active rejection and rollback."""

from datetime import timedelta

import pytest
from alembic import command
from sqlalchemy import text

from itda.authenticity.release import build_release
from itda.authenticity.repository import Repository, RequestConflict
from itda.authenticity.scoring import build_assessment
from itda.authenticity.sources import seal_bundle
from itda.cli.initialize_authenticity_release import ensure_initial_authenticity_release
from itda.db.session import create_database_engine
from tests.authenticity.helpers import NOW
from tests.authenticity.test_intent_and_ranking import assessment
from tests.authenticity.test_publication_scope import selection
from tests.integration.test_daily_glm_refresh_migration import _config


def bundle(directory, *, tag=0, scope="PUBLIC"):
    # Deliberately synthetic transport fixture, never exported from tmp_path.
    original = assessment(1)
    place = original.source.place.model_copy(
        update={"cohort": "initial", "name_ko": "SYNTHETIC DEPLOYMENT CONTRACT FIXTURE"}
    )
    source = seal_bundle(place, original.source.evidence, original.source.parent_source_sha256)
    row = build_assessment(
        source=source,
        judgments=original.judgments,
        rejections=original.rejections,
        policy=original.policy,
        assessed_at=NOW,
    )
    # The one-place helper's fixed ID is replaced by this fixture's ID.
    from itda.authenticity.publication_scope import PublicationSelection
    from itda.domain.canonical import canonical_sha256
    from tests.authenticity.helpers import evidence
    from tests.authenticity.helpers import source as fixed_source

    chosen = selection(fixed_source(evidence()))
    payload = chosen.model_dump(mode="json", exclude={"selection_sha256"})
    payload["analyzed_place_ids"] = [place.place_id]
    payload["decisions"] = []
    chosen = PublicationSelection.model_validate(
        payload | {"selection_sha256": canonical_sha256(payload)}
    )
    release = build_release(
        assessments=(row,),
        directory=directory,
        expected_ids=(place.place_id,),
        parent_manifest_sha256="d" * 64,
        scope=scope,
        publication_selection=chosen,
        created_at=NOW + timedelta(seconds=tag),
    )
    return {
        "ITDA_AUTHENTICITY_RELEASE_DIR": str(directory),
        "ITDA_AUTHENTICITY_RELEASE_SHA256": release.release_sha256,
        "ITDA_AUTHENTICITY_EXPECTED_PLACES": "1",
    }, release


def test_pinned_public_install_redeploy_and_explicit_rollback(postgres_harness, tmp_path):
    command.upgrade(_config(postgres_harness), "head")
    engine = create_database_engine(postgres_harness.dsns["admin"])
    repository = Repository(engine)
    first, a = bundle(tmp_path / "first")
    second, b = bundle(tmp_path / "second", tag=1)
    dsn = postgres_harness.dsns["admin"]
    try:
        with engine.connect() as connection:
            legacy_before = connection.execute(
                text("SELECT to_jsonb(t) FROM app.grounded_release_active t")
            ).all()
        with pytest.raises(ValueError, match="PIN_MISMATCH"):
            ensure_initial_authenticity_release(
                first | {"ITDA_AUTHENTICITY_RELEASE_SHA256": "f" * 64}, admin_dsn=dsn
            )
        assert repository.active_release() is None
        assert ensure_initial_authenticity_release(first, admin_dsn=dsn)["state"] == "activated"
        assert ensure_initial_authenticity_release(first, admin_dsn=dsn)["state"] == "retained"
        with pytest.raises(RequestConflict):
            ensure_initial_authenticity_release(second, admin_dsn=dsn)
        assert repository.active_release() == a
        ensure_initial_authenticity_release(
            second | {"ITDA_AUTHENTICITY_PREVIOUS_RELEASE_SHA256": a.release_sha256}, admin_dsn=dsn
        )
        assert repository.active_release() == b
        ensure_initial_authenticity_release(
            first | {"ITDA_AUTHENTICITY_PREVIOUS_RELEASE_SHA256": b.release_sha256}, admin_dsn=dsn
        )
        assert repository.active_release() == a
        assert repository.get_release(b.release_sha256)[0] == b
        development, _ = bundle(tmp_path / "development", scope="DEVELOPMENT")
        with pytest.raises(ValueError, match="PIN_MISMATCH"):
            ensure_initial_authenticity_release(development, admin_dsn=dsn)
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT to_jsonb(t) FROM app.grounded_release_active t")
                ).all()
                == legacy_before
            )
    finally:
        engine.dispose()
