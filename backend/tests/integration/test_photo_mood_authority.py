"""Real PostgreSQL owner/family, stored mood confirmation and deletion authority."""

from __future__ import annotations

import secrets

import psycopg
import pytest
from psycopg.types.json import Jsonb
from sqlalchemy.exc import DBAPIError

from itda.contracts.visual_mood import MoodChoice, MoodObservation, VisualMoodDimension
from itda.db.photo_mood_repositories import PhotoMoodRepository
from itda.db.session import create_database_engine, create_session_factory
from itda.domain.canonical import canonical_sha256
from itda.domain.visual_mood import build_candidate_set, mood_draft_sha256
from tests.integration.test_phase6_photo_jobs import (
    _force_status,
    _insert_queued_job,
)
from tests.integration.test_phase6_photo_jobs import (
    phase6_roles as _phase6_roles,
)
from tests.integration.test_phase6_photo_jobs import (
    phase6_schema as _phase6_schema,
)

phase6_roles = _phase6_roles
phase6_schema = _phase6_schema

_TABLES = ("photo_mood_job_families", "photo_mood_batches", "photo_mood_confirmations")


@pytest.fixture
def repository(phase6_schema):
    engine = create_database_engine(phase6_schema["job"])
    yield PhotoMoodRepository(create_session_factory(engine))
    engine.dispose()


def _batch(job_id: str, index: int = 1, *, observed: bool = True, image: str | None = None):
    return build_candidate_set(
        job_id=job_id,
        image_index=index,
        image_sha256=image or secrets.token_hex(32),
        observations=tuple(
            MoodObservation(
                dimension=dimension,
                state="OBSERVED" if observed else "UNKNOWN",
                level=(index % 4) if observed else None,
                certainty="HIGH" if observed else "LOW",
            )
            for dimension in VisualMoodDimension
        ),
        provider_id="glm-mood-fixture",
        analysis_kind="MODEL",
        model="glm-5.3-flash",
    )


def _running(repository, dsns, *, images: int = 1):
    job_id, owner = secrets.token_hex(32), "profile:mood:" + secrets.token_hex(8)
    repository.create_job(job_id=job_id, profile_id=owner)
    with psycopg.connect(dsns["job"], autocommit=True) as connection:
        for index in range(1, images + 1):
            stored_name = secrets.token_hex(16)
            connection.execute(
                "SELECT dev_eval.reserve_photo_image_slot_v3(%s,%s,%s,%s,'image/jpeg')",
                (job_id, owner, index, stored_name),
            )
            connection.execute(
                "SELECT dev_eval.commit_photo_image_slot_v3(%s,%s,%s,%s,128)",
                (job_id, owner, index, stored_name),
            )
        _force_status(connection, job_id=job_id, profile_id=owner, to_status="running")
    return job_id, owner


def _succeed(dsns, job_id, owner):
    with psycopg.connect(dsns["job"], autocommit=True) as connection:
        _force_status(
            connection, job_id=job_id, profile_id=owner, to_status="succeeded", cause="success"
        )


def test_atomic_family_creation_owner_check_and_no_historical_upgrade(repository, phase6_schema):
    job, owner = secrets.token_hex(32), "profile:mood-create"
    assert repository.create_job(job_id=job, profile_id=owner) == job
    assert repository.create_job(job_id=job, profile_id=owner) == job
    assert repository.family(job_id=job, profile_id=owner) == "photo-mood-v1"
    with pytest.raises(DBAPIError):
        repository.family(job_id=job, profile_id="profile:other")
    with pytest.raises(DBAPIError):
        repository.create_job(job_id=job, profile_id="profile:other")
    historical = secrets.token_hex(32)
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        _insert_queued_job(connection, job_id=historical, profile_id=owner)
    assert repository.family(job_id=historical, profile_id=owner) is None
    with pytest.raises(DBAPIError):
        repository.create_job(job_id=historical, profile_id=owner)
    assert repository.family(job_id=historical, profile_id=owner) is None


def test_creation_rollback_cannot_leave_an_unbound_generic_job(repository, phase6_schema):
    job, owner = secrets.token_hex(32), "profile:mood-rollback"
    with pytest.raises(RuntimeError), psycopg.connect(phase6_schema["job"]) as connection:
        connection.execute("SELECT dev_eval.create_photo_mood_job_v1(%s,%s)", (job, owner))
        raise RuntimeError("rollback after family insert")
    with psycopg.connect(phase6_schema["job"]) as connection:
        assert (
            connection.execute(
                "SELECT * FROM dev_eval.read_photo_job_v2(%s,%s)", (job, owner)
            ).fetchone()
            is None
        )


def test_stored_moods_confirm_idempotently_and_sql_rejects_changed_choice(
    repository, phase6_schema
):
    job, owner = _running(repository, phase6_schema, images=2)
    batches = (_batch(job, 1), _batch(job, 2))
    with psycopg.connect(phase6_schema["job"]) as connection:
        for batch in reversed(batches):
            assert repository.record_batch(connection, batch=batch, profile_id=owner) == 8
        assert repository.record_batch(connection, batch=batches[0], profile_id=owner) == 0
    _succeed(phase6_schema, job, owner)
    assert repository.read_batches(job_id=job, profile_id=owner) == batches
    assert repository.read_confirmation(job_id=job, profile_id=owner) is None
    choices = tuple(
        MoodChoice(candidate_id=c.candidate_id, included=True)
        for batch in batches
        for c in batch.candidates
    )
    draft = mood_draft_sha256(job_id=job, profile_id=owner, batches=batches)
    first = repository.confirm(job_id=job, profile_id=owner, choices=choices, draft_sha256=draft)
    assert all(mood.value == 38 and mood.distinct_images == 2 for mood in first.moods)
    assert (
        repository.confirm(
            job_id=job, profile_id=owner, choices=tuple(reversed(choices)), draft_sha256=draft
        )
        == first
    )
    assert repository.read_projection(job_id=job, profile_id=owner) == first
    with pytest.raises(DBAPIError):
        repository.confirm(job_id=job, profile_id=owner, choices=(), draft_sha256=draft)


@pytest.mark.parametrize("observed", [True, False])
def test_all_excluded_and_no_observations_are_valid_baseline_receipts(
    repository, phase6_schema, observed
):
    job, owner = _running(repository, phase6_schema)
    batch = _batch(job, observed=observed)
    with psycopg.connect(phase6_schema["job"]) as connection:
        repository.record_batch(connection, batch=batch, profile_id=owner)
    _succeed(phase6_schema, job, owner)
    draft = mood_draft_sha256(job_id=job, profile_id=owner, batches=(batch,))
    choices = (
        tuple(MoodChoice(candidate_id=c.candidate_id, included=False) for c in batch.candidates)
        if observed
        else ()
    )
    confirmed = repository.confirm(
        job_id=job, profile_id=owner, choices=choices, draft_sha256=draft
    )
    assert all(mood.value is None and mood.distinct_images == 0 for mood in confirmed.moods)
    assert repository.read_projection(job_id=job, profile_id=owner) == confirmed


def test_raw_sql_cannot_supply_facts_extra_keys_foreign_choices_or_wrong_draft(
    repository, phase6_schema
):
    job, owner = _running(repository, phase6_schema)
    batch = _batch(job, observed=False)
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        hostile = batch.model_dump(mode="json")
        hostile["candidates"][0]["observation"]["dimension"] = "M3"
        hostile["candidate_set_sha256"] = canonical_sha256(
            {k: v for k, v in hostile.items() if k != "candidate_set_sha256"}
        )
        with pytest.raises(psycopg.Error):
            connection.execute(
                "SELECT dev_eval.record_photo_mood_batch_v1(%s,%s,%s)", (job, owner, Jsonb(hostile))
            )
        # JSON null must not bypass a SQL NOT IN check via three-valued logic.
        for key in ("analysis_kind", "state"):
            malformed = batch.model_dump(mode="json")
            if key == "analysis_kind":
                malformed[key] = None
            else:
                candidate = malformed["candidates"][0]
                candidate["observation"]["state"] = None
                candidate["candidate_id"] = canonical_sha256(
                    {
                        "job_id": job,
                        "image": malformed["payload_sha256"],
                        "observation": candidate["observation"],
                        "provider_id": malformed["provider_id"],
                        "policy_sha256": malformed["policy_sha256"],
                    }
                )
            malformed["candidate_set_sha256"] = canonical_sha256(
                {k: v for k, v in malformed.items() if k != "candidate_set_sha256"}
            )
            with pytest.raises(psycopg.Error):
                connection.execute(
                    "SELECT dev_eval.record_photo_mood_batch_v1(%s,%s,%s)",
                    (job, owner, Jsonb(malformed)),
                )
        with pytest.raises(psycopg.Error):
            repository.record_batch(connection, batch=batch, profile_id="profile:other")
        repository.record_batch(connection, batch=batch, profile_id=owner)
    _succeed(phase6_schema, job, owner)
    draft = mood_draft_sha256(job_id=job, profile_id=owner, batches=(batch,))
    bad_choices = (
        [{"candidate_id": "f" * 64, "included": True}],
        [{"candidate_id": batch.candidates[0].candidate_id, "included": True}],
        [{"candidate_id": batch.candidates[0].candidate_id, "included": False, "value": 100}],
    )
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        for choices in bad_choices:
            with pytest.raises(psycopg.Error):
                connection.execute(
                    "SELECT dev_eval.confirm_photo_moods_v1(%s,%s,%s,%s)",
                    (job, owner, Jsonb(choices), draft),
                )
        with pytest.raises(psycopg.Error):
            connection.execute(
                "SELECT dev_eval.confirm_photo_moods_v1(%s,%s,'[]'::jsonb,%s)",
                (job, owner, "f" * 64),
            )


def test_duplicate_image_weight_and_explicit_deletion_purge(
    repository, phase6_schema, postgres_harness
):
    job, owner = _running(repository, phase6_schema, images=2)
    first = _batch(job, 1)
    second = build_candidate_set(
        job_id=job,
        image_index=2,
        image_sha256=first.payload_sha256,
        observations=tuple(c.observation for c in first.candidates),
        provider_id=first.provider_id,
        analysis_kind="MODEL",
        model="glm-5.3-flash",
    )
    with psycopg.connect(phase6_schema["job"]) as connection:
        repository.record_batch(connection, batch=first, profile_id=owner)
        repository.record_batch(connection, batch=second, profile_id=owner)
    _succeed(phase6_schema, job, owner)
    choices = tuple(
        MoodChoice(candidate_id=c.candidate_id, included=True) for c in first.candidates
    )
    result = repository.confirm(
        job_id=job,
        profile_id=owner,
        choices=choices,
        draft_sha256=mood_draft_sha256(job_id=job, profile_id=owner, batches=(first, second)),
    )
    assert all(m.distinct_images == 1 and m.value == 25 for m in result.moods)
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        _force_status(
            connection, job_id=job, profile_id=owner, to_status="deleted", cause="explicit_deletion"
        )
    with postgres_harness.connect("admin") as connection:
        for table in ("photo_mood_batches", "photo_mood_confirmations"):
            assert connection.execute(
                f"SELECT count(*) FROM dev_eval.{table} WHERE job_id=%s", (job,)
            ).fetchone() == (0,)
    with pytest.raises(DBAPIError):
        repository.read_projection(job_id=job, profile_id=owner)


def test_no_role_has_direct_mood_table_authority_or_public_function_execute(
    phase6_schema, postgres_harness
):
    for capability in ("runtime", "job", "ledger"):
        with psycopg.connect(phase6_schema[capability], autocommit=True) as connection:
            for table in _TABLES:
                for statement in (
                    f"SELECT * FROM dev_eval.{table}",
                    f"INSERT INTO dev_eval.{table} DEFAULT VALUES",
                    f"UPDATE dev_eval.{table} SET profile_id='profile:illegal'",
                    f"DELETE FROM dev_eval.{table}",
                    f"TRUNCATE dev_eval.{table}",
                ):
                    with pytest.raises(psycopg.errors.InsufficientPrivilege):
                        connection.execute(statement)
            if capability != "job":
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    connection.execute(
                        "SELECT dev_eval.create_photo_mood_job_v1(%s,'profile:denied')",
                        (secrets.token_hex(32),),
                    )
    with postgres_harness.connect("admin") as connection:
        rows = connection.execute("""SELECT p.proname, p.prosecdef, r.rolname,
            EXISTS(SELECT 1 FROM aclexplode(p.proacl) x
                WHERE x.grantee=0 AND x.privilege_type='EXECUTE')
            FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner
            JOIN pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname='dev_eval' AND p.proname IN
            ('create_photo_mood_job_v1','record_photo_mood_batch_v1','confirm_photo_moods_v1')""").fetchall()
    assert len(rows) == 3
    assert all(
        security and owner == "itda_photo_write_authority" and not public
        for _, security, owner, public in rows
    )


def test_actual_gateway_sanitizes_confirms_empty_mood_and_deletes(
    phase6_schema, postgres_harness, tmp_path
):
    import asyncio
    from io import BytesIO

    from PIL import Image

    from itda.api.routes.photo import CURRENT_PHOTO_CONSENT_NOTICE, PhotoLifecycleGateway
    from itda.photo.provider.mood import SyntheticMoodProvider

    class InspectingSyntheticProvider(SyntheticMoodProvider):
        seen = False

        def analyze(self, **kwargs):
            # Retain the production synthetic contract: every dimension UNKNOWN.
            sanitized = kwargs["image_png"]
            assert sanitized.startswith(b"\x89PNG\r\n\x1a\n")
            assert b"private fixture metadata" not in sanitized
            with Image.open(BytesIO(sanitized)) as inspected:
                assert inspected.mode == "RGB"
                assert not inspected.getexif()
            self.seen = True
            return super().analyze(**kwargs)

    root = tmp_path / "quarantine"
    root.mkdir(mode=0o700)
    engine = create_database_engine(phase6_schema["job"])
    provider = InspectingSyntheticProvider()
    gateway = PhotoLifecycleGateway(
        factory=create_session_factory(engine),
        service_dsn=phase6_schema["job"],
        quarantine_root=root,
        runtime_role=postgres_harness.role_names["runtime"],
        builder_role=postgres_harness.role_names["dev"],
        mood_enabled=True,
        synthetic_test_mode=True,
        mood_provider=provider,
    )
    try:
        gateway.verify_service_authority()
        owner = "profile:gateway-mood:" + secrets.token_hex(8)
        created = gateway.create_job(
            profile_id=owner,
            consent_accepted=True,
            consent_version=CURRENT_PHOTO_CONSENT_NOTICE.consent_version,
        )
        job = str(created["job_id"])
        assert created["analysis_family"] == "photo-mood-v1"
        buffer = BytesIO()
        source = Image.new("RGB", (96, 96), (50, 100, 70))
        exif = Image.Exif()
        exif[0x010E] = "private fixture metadata"
        source.save(buffer, format="JPEG", exif=exif)
        payload = buffer.getvalue()

        async def chunks():
            yield payload

        asyncio.run(
            gateway.store_image_stream(
                job_id=job,
                job_directory=job,
                profile_id=owner,
                image_index=1,
                chunks=chunks(),
                declared_byte_length=len(payload),
                media_type="image/jpeg",
            )
        )
        gateway.submit_job(job_id=job, profile_id=owner)
        assert provider.seen
        assert gateway.read_job_state(job_id=job, profile_id=owner)["state"] == "succeeded"
        review = gateway.mood_service.review(job_id=job, profile_id=owner)
        assert len(review.batches) == 1 and review.batches[0].analysis_kind == "SYNTHETIC"
        confirmed = gateway.mood_service.confirm(
            job_id=job, profile_id=owner, choices=(), draft_sha256=review.draft_sha256
        )
        assert all(mood.value is None for mood in confirmed.moods)
        # Terminal success already removes original quarantine bytes.
        assert not (root / job).exists()
        gateway.delete_job(job_id=job, profile_id=owner)
        assert gateway.read_job_state(job_id=job, profile_id=owner)["state"] == "deleted"
        assert not (root / job).exists()
        with postgres_harness.connect("admin") as connection:
            for table in ("photo_mood_batches", "photo_mood_confirmations"):
                assert connection.execute(
                    f"SELECT count(*) FROM dev_eval.{table} WHERE job_id=%s", (job,)
                ).fetchone() == (0,)
    finally:
        engine.dispose()


@pytest.mark.parametrize("cohort", ["disabled-new", "unconfigured-new", "pending-legacy"])
def test_production_unavailable_and_pending_legacy_jobs_clean_up_without_trait_inference(
    phase6_schema, postgres_harness, tmp_path, cohort
):
    import asyncio
    from io import BytesIO

    from PIL import Image

    from itda.api.routes.photo import CURRENT_PHOTO_CONSENT_NOTICE, PhotoLifecycleGateway
    from itda.photo.provider.live import PhotoLiveAnalysisUnavailable

    class ForbiddenProvider:
        def analyze(self, **_kwargs):
            pytest.fail("production invoked legacy trait inference")

    root = tmp_path / "quarantine"
    root.mkdir(mode=0o700)
    engine = create_database_engine(phase6_schema["job"])
    gateway = PhotoLifecycleGateway(
        factory=create_session_factory(engine),
        service_dsn=phase6_schema["job"],
        quarantine_root=root,
        runtime_role=postgres_harness.role_names["runtime"],
        builder_role=postgres_harness.role_names["dev"],
        mood_enabled=cohort != "disabled-new",
        provider=ForbiddenProvider(),
    )
    owner = "profile:unavailable-mood:" + secrets.token_hex(8)
    try:
        if cohort == "pending-legacy":
            job = secrets.token_hex(32)
            with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
                _insert_queued_job(connection, job_id=job, profile_id=owner)
            expected_family = None
        else:
            created = gateway.create_job(
                profile_id=owner,
                consent_accepted=True,
                consent_version=CURRENT_PHOTO_CONSENT_NOTICE.consent_version,
            )
            job = str(created["job_id"])
            assert created["analysis_family"] == "photo-mood-v1"
            expected_family = "photo-mood-v1"
        assert gateway._mood_store.family(job_id=job, profile_id=owner) == expected_family
        buffer = BytesIO()
        Image.new("RGB", (96, 96), (50, 100, 70)).save(buffer, format="PNG")
        payload = buffer.getvalue()

        async def chunks():
            yield payload

        asyncio.run(
            gateway.store_image_stream(
                job_id=job,
                job_directory=job,
                profile_id=owner,
                image_index=1,
                chunks=chunks(),
                declared_byte_length=len(payload),
                media_type="image/png",
            )
        )
        assert (root / job).exists()
        with pytest.raises(PhotoLiveAnalysisUnavailable):
            gateway.submit_job(job_id=job, profile_id=owner)
        state = gateway.read_job_state(job_id=job, profile_id=owner)
        assert state["state"] == "failed" and state["terminal_cause"] == "provider_error"
        assert state["cleanup_pending"] is False
        assert state.get("analysis_family") == expected_family
        assert not (root / job).exists()
        with psycopg.connect(phase6_schema["job"]) as connection:
            assert connection.execute(
                "SELECT reason_code FROM dev_eval.list_photo_deletion_ledger_v3(%s,%s)",
                (job, owner),
            ).fetchall() == [("PHOTO_ANALYSIS_UNAVAILABLE",)]
        with postgres_harness.connect("admin") as connection:
            for table in ("photo_mood_batches", "photo_trait_candidates"):
                assert connection.execute(
                    f"SELECT count(*) FROM dev_eval.{table} WHERE job_id=%s", (job,)
                ).fetchone() == (0,)
        # Historical ownership/deletion remains usable after the fail-closed submit.
        gateway.delete_job(job_id=job, profile_id=owner)
        assert gateway.read_job_state(job_id=job, profile_id=owner)["state"] == "deleted"
    finally:
        engine.dispose()
