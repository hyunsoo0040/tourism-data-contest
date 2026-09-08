"""Wave 0 controlled-RED contracts for Phase 6 trait review persistence.

Proves immutable model candidate rows stay separate from user-confirmed rows:
edits and exclusions never rewrite model text, explicit batch confirmation
alone creates confirmed values, reload preserves provenance, zero included
values fall back to the original no-photo profile, and projection reads only
nonempty included confirmed values. The module fails only on the absent
Phase 6 owners (``itda.db.photo_repositories``/``itda.photo.jobs``).
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.orm import sessionmaker

from itda.db.session import sqlalchemy_url_from_dsn
from tests.conftest import PostgresHarness
from tests.integration.profile_release_test_support import (
    ensure_photo_lifecycle_roles,
    ensure_profile_release_authority_roles,
    ensure_profile_session_roles,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ALEMBIC_CONFIG = REPOSITORY_ROOT / "backend" / "alembic.ini"

JOB_ID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0" * 2
PROFILE_ID = "anonymous:trait-review-profile"


def _migration_config(postgres_harness: PostgresHarness) -> Config:
    config = Config(str(ALEMBIC_CONFIG))
    config.set_main_option(
        "sqlalchemy.url",
        sqlalchemy_url_from_dsn(postgres_harness.dsns["admin"]).render_as_string(
            hide_password=False
        ),
    )
    config.attributes["database_name"] = postgres_harness.database_name
    config.attributes["profile_release_authorization_hmac_key"] = "41" * 32
    for capability in ("runtime", "dev", "sealer", "evaluator"):
        config.attributes[f"{capability}_role"] = postgres_harness.role_names[capability]
    config.attributes["label_builder_role"] = postgres_harness.role_names["dev"]
    return config


@pytest.fixture(scope="module")
def phase6_review_schema(postgres_harness: PostgresHarness) -> Iterator[None]:
    """Migrate the module's harness database to head once.

    Migration 0020 is intentionally irreversible, so teardown truncates the
    review state instead of downgrading.
    """

    ensure_profile_release_authority_roles(postgres_harness)
    ensure_profile_session_roles(postgres_harness)
    ensure_photo_lifecycle_roles(postgres_harness)
    command.upgrade(_migration_config(postgres_harness), "head")
    yield
    with postgres_harness.connect("admin", autocommit=True) as connection:
        connection.execute("TRUNCATE dev_eval.photo_trait_candidates CASCADE")
        connection.execute("TRUNCATE dev_eval.photo_confirmed_traits CASCADE")
        connection.execute("TRUNCATE dev_eval.photo_review_drafts CASCADE")
        connection.execute("TRUNCATE dev_eval.photo_confirmation_receipts CASCADE")
        connection.execute("TRUNCATE dev_eval.photo_job_dispatch_markers CASCADE")
        connection.execute("TRUNCATE dev_eval.photo_jobs CASCADE")


@pytest.fixture
def phase6_review_stores(
    postgres_harness: PostgresHarness, phase6_review_schema: None
) -> Iterator[tuple[object, object]]:
    """Fresh review stores per test with the parent job row reseeded.

    The shared JOB_ID's durable parent job row is part of the review
    store's setup precondition: candidate/confirmed rows always belong
    to one owned job. Prior tests' review rows are purged so each test
    observes exactly its own writes. Stores run under the fixed photo
    service principal because migration 0020 made exact SECURITY
    DEFINER functions the only write path.
    """

    fixed = ensure_photo_lifecycle_roles(postgres_harness)
    with postgres_harness.connect("admin", autocommit=True) as connection:
        connection.execute("TRUNCATE dev_eval.photo_trait_candidates CASCADE")
        connection.execute("TRUNCATE dev_eval.photo_confirmed_traits CASCADE")
        connection.execute("TRUNCATE dev_eval.photo_review_drafts CASCADE")
        connection.execute("TRUNCATE dev_eval.photo_confirmation_receipts CASCADE")
        connection.execute("TRUNCATE dev_eval.photo_job_dispatch_markers CASCADE")
        connection.execute("TRUNCATE dev_eval.photo_jobs CASCADE")
    import psycopg as _psycopg
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    admin_info = conninfo_to_dict(postgres_harness.dsns["admin"])
    service_dsn = make_conninfo(
        **(admin_info | {"user": fixed["service_role"], "password": fixed["service_password"]})
    )
    with _psycopg.connect(service_dsn, autocommit=True) as connection:
        connection.execute(
            "SELECT dev_eval.create_photo_job_v3(%s, %s, NULL)",
            (JOB_ID, PROFILE_ID),
        )
        connection.execute(
            "SELECT dev_eval.claim_photo_job_filesystem_binding_v3(%s, %s)",
            (JOB_ID, PROFILE_ID),
        )
        connection.execute(
            "SELECT dev_eval.transition_photo_job_nonterminal_v3"
            "(%s, %s, 'queued', 'running', now() + interval '5 minutes')",
            (JOB_ID, PROFILE_ID),
        )
        canonical_operation = f"photo-terminal-v1|{JOB_ID}|{PROFILE_ID}|success|PHOTO_SUCCESS"
        operation_first = hashlib.md5(
            canonical_operation.encode(), usedforsecurity=False
        ).hexdigest()
        operation_second = hashlib.md5(
            f"{canonical_operation}|second-half".encode(), usedforsecurity=False
        ).hexdigest()
        operation_key = operation_first + operation_second
        residue_digest = hashlib.sha256(f"photo-residue-v1|{operation_key}|0".encode()).hexdigest()
        connection.execute(
            "SELECT dev_eval.append_photo_deletion_ledger_v3"
            "(%s, %s, 'success', 'PHOTO_SUCCESS', %s, 0, %s)",
            (JOB_ID, PROFILE_ID, operation_key, residue_digest),
        )
        connection.execute(
            "SELECT dev_eval.finalize_photo_job_terminal_v3"
            "(%s, %s, 'running', 'succeeded', 'success', 'PHOTO_SUCCESS', %s, %s)",
            (JOB_ID, PROFILE_ID, operation_key, residue_digest),
        )
    yield _review_stores(postgres_harness, fixed)


def _review_stores(postgres_harness: PostgresHarness, _schema: object = None):
    """Open the Phase 6 candidate/confirmed store pair under test."""

    from itda.db.photo_repositories import (
        PhotoConfirmedTraitStore,
        PhotoTraitCandidateStore,
    )

    engine_session: sessionmaker = sessionmaker(
        bind=_engine_for(postgres_harness), expire_on_commit=False
    )
    return (
        PhotoTraitCandidateStore(engine_session),
        PhotoConfirmedTraitStore(engine_session),
    )


def _engine_for(postgres_harness: PostgresHarness):
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    from sqlalchemy import create_engine

    from itda.db.session import sqlalchemy_url_from_dsn
    from tests.integration.profile_release_test_support import ensure_photo_lifecycle_roles

    fixed = ensure_photo_lifecycle_roles(postgres_harness)
    admin_info = conninfo_to_dict(postgres_harness.dsns["admin"])
    service_dsn = make_conninfo(
        **(admin_info | {"user": fixed["service_role"], "password": fixed["service_password"]})
    )
    return create_engine(sqlalchemy_url_from_dsn(service_dsn))


def _candidate_row(
    *,
    candidate_id: str = "aa" * 32,
    trait_id: str = "M5",
    text_ko: str = "조용한 산책로",
) -> dict[str, object]:
    return {
        "job_id": JOB_ID,
        "candidate_id": candidate_id,
        "trait_id": trait_id,
        "text_ko": text_ko,
        "candidate_set_sha256": hashlib.sha256(text_ko.encode()).hexdigest(),
    }


def _drain(store: object, job_id: str, profile_id: str = PROFILE_ID) -> list[dict[str, object]]:
    return [
        row.model_dump(mode="json")
        for row in store.list_for_job(job_id, profile_id)  # type: ignore[union-attr]
    ]


def test_candidate_rows_persist_and_survive_reload(
    postgres_harness: PostgresHarness, phase6_review_stores: tuple[object, object]
) -> None:
    candidate_store, confirmed_store = phase6_review_stores
    batch = [
        _candidate_row(),
        _candidate_row(candidate_id="bb" * 32, trait_id="M2", text_ko="역사 이야기"),
    ]
    candidate_store.append_batch(JOB_ID, batch, profile_id=PROFILE_ID)  # type: ignore[union-attr]
    assert len(_drain(candidate_store, JOB_ID)) == 2
    assert len(_drain(confirmed_store, JOB_ID)) == 0

    reopened_store, _ = _review_stores(postgres_harness, phase6_review_stores)
    reloaded = _drain(reopened_store, JOB_ID)
    assert [row["candidate_id"] for row in reloaded] == ["aa" * 32, "bb" * 32]
    assert reloaded[0]["text_ko"] == "조용한 산책로"


def test_edits_and_exclusions_never_rewrite_model_candidate_text(
    postgres_harness: PostgresHarness, phase6_review_stores: tuple[object, object]
) -> None:
    candidate_store, _ = phase6_review_stores
    candidate_store.append_batch(JOB_ID, [_candidate_row()], profile_id=PROFILE_ID)  # type: ignore[union-attr]

    candidate_store.record_edit(JOB_ID, PROFILE_ID, "aa" * 32, edited_text_ko="한적한 숲길")  # type: ignore[union-attr]
    candidate_store.record_exclusion(JOB_ID, PROFILE_ID, "aa" * 32)  # type: ignore[union-attr]

    rows = {row["candidate_id"]: row for row in _drain(candidate_store, JOB_ID)}
    original = rows["aa" * 32]
    assert original["text_ko"] == "조용한 산책로", "model text must stay immutable"
    assert original["edited_text_ko"] == "한적한 숲길"
    assert original["excluded"] is True
    assert (
        original["candidate_set_sha256"] == hashlib.sha256("조용한 산책로".encode()).hexdigest()
    ), "candidate digest must keep binding original model text"


def test_only_explicit_batch_confirmation_creates_confirmed_values(
    postgres_harness: PostgresHarness, phase6_review_stores: tuple[object, object]
) -> None:
    candidate_store, confirmed_store = phase6_review_stores
    batch = [
        _candidate_row(),
        _candidate_row(candidate_id="bb" * 32, trait_id="M2", text_ko="역사 이야기"),
    ]
    candidate_store.append_batch(JOB_ID, batch, profile_id=PROFILE_ID)  # type: ignore[union-attr]

    candidate_store.record_edit(JOB_ID, PROFILE_ID, "aa" * 32, edited_text_ko="한적한 숲길")  # type: ignore[union-attr]
    candidate_store.record_exclusion(JOB_ID, PROFILE_ID, "bb" * 32)  # type: ignore[union-attr]

    confirmed_store.confirm_batch(
        JOB_ID,
        [
            {
                "trait_id": "M5",
                "text_ko": "한적한 숲길",
                "source_candidate_id": "aa" * 32,
                "included": True,
            }
        ],
        profile_id=PROFILE_ID,
    )  # type: ignore[union-attr]

    confirmed = _drain(confirmed_store, JOB_ID)
    assert len(confirmed) == 1
    assert confirmed[0]["text_ko"] == "한적한 숲길"
    assert confirmed[0]["included"] is True
    assert confirmed[0]["source_candidate_id"] == "aa" * 32


def test_edited_and_excluded_provenance_survives_reload(
    postgres_harness: PostgresHarness, phase6_review_stores: tuple[object, object]
) -> None:
    candidate_store, confirmed_store = phase6_review_stores
    batch = [
        _candidate_row(),
        _candidate_row(candidate_id="bb" * 32, trait_id="M2", text_ko="역사 이야기"),
    ]
    candidate_store.append_batch(JOB_ID, batch, profile_id=PROFILE_ID)  # type: ignore[union-attr]
    candidate_store.record_edit(JOB_ID, PROFILE_ID, "aa" * 32, edited_text_ko="한적한 숲길")  # type: ignore[union-attr]
    candidate_store.record_exclusion(JOB_ID, PROFILE_ID, "bb" * 32)  # type: ignore[union-attr]
    confirmed_store.confirm_batch(
        JOB_ID,
        [
            {
                "trait_id": "M5",
                "text_ko": "한적한 숲길",
                "source_candidate_id": "aa" * 32,
                "included": True,
            }
        ],
        profile_id=PROFILE_ID,
    )  # type: ignore[union-attr]

    reopened_candidates, reopened_confirmed = _review_stores(postgres_harness, phase6_review_stores)
    candidate_rows = {row["candidate_id"]: row for row in _drain(reopened_candidates, JOB_ID)}
    assert candidate_rows["aa" * 32]["provenance"] == "MODEL_CANDIDATE"
    assert candidate_rows["aa" * 32]["edited_text_ko"] == "한적한 숲길"
    assert candidate_rows["bb" * 32]["provenance"] == "MODEL_CANDIDATE"
    assert candidate_rows["bb" * 32]["excluded"] is True

    confirmed_rows = _drain(reopened_confirmed, JOB_ID)
    assert [row["provenance"] for row in confirmed_rows] == ["USER_CONFIRMED"]
    assert confirmed_rows[0]["text_ko"] != candidate_rows["aa" * 32]["text_ko"]


def test_projection_query_reads_only_included_confirmed_values(
    postgres_harness: PostgresHarness, phase6_review_stores: tuple[object, object]
) -> None:
    candidate_store, confirmed_store = phase6_review_stores
    candidate_store.append_batch(
        JOB_ID,
        [
            _candidate_row(),
            _candidate_row(candidate_id="bb" * 32, trait_id="M2", text_ko="역사 이야기"),
            _candidate_row(candidate_id="cc" * 32, trait_id="M3", text_ko="제주 바다"),
        ],
        profile_id=PROFILE_ID,
    )  # type: ignore[union-attr]
    confirmed_store.confirm_batch(
        JOB_ID,
        [
            {
                "trait_id": "M5",
                "text_ko": "한적한 숲길",
                "source_candidate_id": "aa" * 32,
                "included": True,
            },
            {
                "trait_id": "M2",
                "text_ko": "빈 문구",
                "source_candidate_id": "bb" * 32,
                "included": True,
                "text_ko_is_blank": True,
            },
            {
                "trait_id": "M3",
                "text_ko": "제주 바다",
                "source_candidate_id": "cc" * 32,
                "included": False,
            },
        ],
        profile_id=PROFILE_ID,
    )  # type: ignore[union-attr]

    included = confirmed_store.list_included_for_projection(JOB_ID, PROFILE_ID)  # type: ignore[union-attr]
    assert [(row.trait_id, row.text_ko) for row in included] == [("M5", "한적한 숲길")], (
        "projection must read only nonempty included confirmed values"
    )


def test_zero_included_values_keep_original_no_photo_profile(
    postgres_harness: PostgresHarness, phase6_review_stores: tuple[object, object]
) -> None:
    from itda.domain.photo_projection import combine_confirmed_photo_traits

    _candidate_store, confirmed_store = phase6_review_stores
    _candidate_store.append_batch(
        JOB_ID,
        [_candidate_row(candidate_id="cc" * 32, trait_id="M3", text_ko="제주 바다")],
        profile_id=PROFILE_ID,
    )  # type: ignore[union-attr]
    confirmed_store.confirm_batch(
        JOB_ID,
        [
            {
                "trait_id": "M3",
                "text_ko": "제주 바다",
                "source_candidate_id": "cc" * 32,
                "included": False,
            }
        ],
        profile_id=PROFILE_ID,
    )  # type: ignore[union-attr]

    result = combine_confirmed_photo_traits(
        confirmed_traits=confirmed_store.list_included_for_projection(JOB_ID, PROFILE_ID),  # type: ignore[union-attr]
        images_count=1,
    )
    assert result.photo_trait_values == (), "excluded-only input must produce no photo traits"
    assert result.blend_applied is False, "no-photo blend must be skipped for empty input"


def test_repository_writes_use_functions_not_direct_dml(
    postgres_harness: PostgresHarness, phase6_review_stores: tuple[object, object]
) -> None:
    """Candidate/confirmed stores mutate only through 0020 functions."""

    import inspect

    from itda.db import photo_repositories

    source = inspect.getsource(photo_repositories)
    for forbidden in (
        "INSERT INTO dev_eval.photo_trait_candidates",
        "INSERT INTO dev_eval.photo_confirmed_traits",
        "UPDATE dev_eval.photo_trait_candidates",
        "UPDATE dev_eval.photo_confirmed_traits",
        "INSERT INTO dev_eval.photo_jobs",
        "UPDATE dev_eval.photo_jobs",
    ):
        assert forbidden not in source, f"repository must not issue direct DML: {forbidden}"
    for required in (
        "create_photo_job_v3",
        "record_photo_candidate_batch_v3",
        "annotate_photo_candidate_v3",
        "confirm_photo_traits_v3",
    ):
        assert required in source, f"repository must call the exact function: {required}"


def test_candidate_store_rejects_oversized_and_duplicate_batches(
    postgres_harness: PostgresHarness, phase6_review_stores: tuple[object, object]
) -> None:
    """The typed batch bound is 1..6 with unique candidate identities."""

    from itda.db.photo_repositories import PhotoJobStoreError

    candidate_store, _ = phase6_review_stores
    oversized = [_candidate_row(candidate_id=f"{index:02x}" * 32) for index in range(7)]
    with pytest.raises(PhotoJobStoreError):
        candidate_store.append_batch(JOB_ID, oversized)  # type: ignore[union-attr]

    duplicate = [
        _candidate_row(),
        _candidate_row(trait_id="M2", text_ko="역사 이야기"),
    ]
    with pytest.raises(PhotoJobStoreError):
        candidate_store.append_batch(JOB_ID, duplicate)  # type: ignore[union-attr]

    empty: list[dict[str, object]] = []
    with pytest.raises(PhotoJobStoreError):
        candidate_store.append_batch(JOB_ID, empty)  # type: ignore[union-attr]


def test_review_draft_store_save_read_and_discard(
    postgres_harness: PostgresHarness, phase6_review_stores: tuple[object, object]
) -> None:
    """Owned draft CAS/read/discard with bounded annotations survives reload."""

    from itda.db.photo_repositories import (
        PhotoReviewDraftStore,
        ReviewDraftEntry,
        ReviewDraftNotFound,
    )

    candidate_store, _ = phase6_review_stores
    candidate_store.append_batch(JOB_ID, [_candidate_row()], profile_id=PROFILE_ID)  # type: ignore[union-attr]
    factory = candidate_store._factory  # type: ignore[attr-defined]
    draft_store = PhotoReviewDraftStore(factory)

    digest = "ab" * 32
    entries = (
        ReviewDraftEntry(candidate_id="aa" * 32, edited_text_ko="한적한 숲길", excluded=False),
    )
    saved = draft_store.save(JOB_ID, PROFILE_ID, draft_digest=digest, entries=entries)
    assert saved is True
    saved_again = draft_store.save(JOB_ID, PROFILE_ID, draft_digest=digest, entries=entries)
    assert saved_again is True

    read = draft_store.read_owned(JOB_ID, PROFILE_ID)
    assert read is not None
    assert read.draft_digest == digest
    assert [entry.edited_text_ko for entry in read.entries] == ["한적한 숲길"]

    with pytest.raises(ReviewDraftNotFound):
        draft_store.read_owned(JOB_ID, "anonymous:attacker-profile")

    assert draft_store.discard(JOB_ID, PROFILE_ID) is True
    assert draft_store.discard(JOB_ID, PROFILE_ID) is False


def test_confirm_returns_atomic_opaque_receipt(
    postgres_harness: PostgresHarness, phase6_review_stores: tuple[object, object]
) -> None:
    """Atomic confirm yields one opaque receipt; repeat is idempotent."""

    from itda.db.photo_repositories import PhotoConfirmedTraitStore, ReceiptRecord

    candidate_store, confirmed_store = phase6_review_stores
    candidate_store.append_batch(JOB_ID, [_candidate_row()], profile_id=PROFILE_ID)  # type: ignore[union-attr]
    assert isinstance(confirmed_store, PhotoConfirmedTraitStore)

    first = confirmed_store.confirm_batch(  # type: ignore[union-attr]
        JOB_ID,
        [
            {
                "trait_id": "M5",
                "text_ko": "한적한 숲길",
                "source_candidate_id": "aa" * 32,
                "included": True,
            }
        ],
        profile_id=PROFILE_ID,
    )
    assert isinstance(first, ReceiptRecord)
    assert first.included_count == 1
    assert len(first.receipt_id) == 64
    assert first.receipt_id != JOB_ID

    second = confirmed_store.confirm_batch(  # type: ignore[union-attr]
        JOB_ID,
        [
            {
                "trait_id": "M5",
                "text_ko": "한적한 숲길",
                "source_candidate_id": "aa" * 32,
                "included": True,
            }
        ],
        profile_id=PROFILE_ID,
    )
    assert second.receipt_id == first.receipt_id, "identical confirmation is idempotent"


def test_all_excluded_confirmation_is_valid_zero_included_receipt(
    postgres_harness: PostgresHarness, phase6_review_stores: tuple[object, object]
) -> None:
    """All-excluded input confirms to a zero-included receipt."""

    from itda.db.photo_repositories import ReceiptRecord

    candidate_store, confirmed_store = phase6_review_stores
    candidate_store.append_batch(
        JOB_ID,
        [_candidate_row(candidate_id="cc" * 32, trait_id="M3", text_ko="제주 바다")],
        profile_id=PROFILE_ID,
    )  # type: ignore[union-attr]
    receipt = confirmed_store.confirm_batch(  # type: ignore[union-attr]
        JOB_ID,
        [
            {
                "trait_id": "M3",
                "text_ko": "제주 바다",
                "source_candidate_id": "cc" * 32,
                "included": False,
            }
        ],
        profile_id=PROFILE_ID,
    )
    assert isinstance(receipt, ReceiptRecord)
    assert receipt.included_count == 0


def test_gateway_rejects_mismatched_photo_service_identity(
    postgres_harness: PostgresHarness, phase6_review_schema: None
) -> None:
    """Gateway construction verifies the exact photo service DSN identity."""

    import inspect

    from itda.api.routes import photo as photo_routes

    source = inspect.getsource(photo_routes.PhotoLifecycleGateway)
    for required in (
        "verify_service_authority",
        "session_user",
        "rolcanlogin",
        "rolinherit",
        "pg_has_role",
        "has_schema_privilege",
        "has_function_privilege",
    ):
        assert required in source, (
            f"gateway startup must verify exact service authority: {required}"
        )
    assert "ITDA_DATABASE_URL" not in inspect.getsource(
        photo_routes.PhotoLifecycleGateway.__init__
    ), "the photo gateway must never bind the runtime application DSN"


def test_gateway_startup_rejects_foreign_session_user(
    postgres_harness: PostgresHarness, phase6_review_schema: None
) -> None:
    """A gateway built on the runtime DSN must refuse to serve."""

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from itda.api.routes.photo import PhotoLifecycleGateway
    from itda.db.session import sqlalchemy_url_from_dsn

    runtime_engine = create_engine(sqlalchemy_url_from_dsn(postgres_harness.dsns["runtime"]))
    gateway = PhotoLifecycleGateway(
        factory=sessionmaker(bind=runtime_engine, expire_on_commit=False),
        service_dsn=postgres_harness.dsns["runtime"],
        quarantine_root=_tmp_quarantine_root(),
        runtime_role=postgres_harness.role_names["runtime"],
        builder_role=postgres_harness.role_names["dev"],
    )
    with pytest.raises(RuntimeError, match="photo service authority"):
        gateway.verify_service_authority()


def _tmp_quarantine_root() -> Path:
    import tempfile

    root = Path(tempfile.mkdtemp(prefix="itda-photo-quarantine-"))
    root.chmod(0o700)
    return root


def test_gateway_startup_rejects_owner_only_allowed_name_overload(
    postgres_harness: PostgresHarness, phase6_review_schema: None
) -> None:
    import psycopg
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from itda.api.routes.photo import PhotoLifecycleGateway
    from itda.db.session import sqlalchemy_url_from_dsn
    from tests.integration.profile_release_test_support import ensure_photo_lifecycle_roles

    fixed = ensure_photo_lifecycle_roles(postgres_harness)
    admin_info = conninfo_to_dict(postgres_harness.dsns["admin"])
    service_dsn = make_conninfo(
        **(admin_info | {"user": fixed["service_role"], "password": fixed["service_password"]})
    )
    with psycopg.connect(postgres_harness.dsns["admin"], autocommit=True) as admin:
        admin.execute(
            "CREATE FUNCTION dev_eval.confirm_photo_traits_v3(jsonb) "
            "RETURNS boolean LANGUAGE sql AS 'SELECT true'"
        )
        admin.execute(
            "REVOKE ALL ON FUNCTION dev_eval.confirm_photo_traits_v3(jsonb) "
            "FROM PUBLIC, itda_photo_service"
        )
    try:
        engine = create_engine(sqlalchemy_url_from_dsn(service_dsn))
        gateway = PhotoLifecycleGateway(
            factory=sessionmaker(bind=engine, expire_on_commit=False),
            service_dsn=service_dsn,
            quarantine_root=_tmp_quarantine_root(),
            runtime_role=postgres_harness.role_names["runtime"],
            builder_role=postgres_harness.role_names["dev"],
        )
        with pytest.raises(RuntimeError, match="unexpected photo function"):
            gateway.verify_service_authority()
        engine.dispose()
    finally:
        with psycopg.connect(postgres_harness.dsns["admin"], autocommit=True) as admin:
            admin.execute("DROP FUNCTION dev_eval.confirm_photo_traits_v3(jsonb)")


def test_gateway_startup_rejects_post_migration_membership_drift(
    postgres_harness: PostgresHarness, phase6_review_schema: None
) -> None:
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from itda.api.routes.photo import PhotoLifecycleGateway
    from itda.db.session import sqlalchemy_url_from_dsn
    from tests.integration.profile_release_test_support import ensure_photo_lifecycle_roles

    fixed = ensure_photo_lifecycle_roles(postgres_harness)
    admin_info = conninfo_to_dict(postgres_harness.dsns["admin"])
    service_dsn = make_conninfo(
        **(admin_info | {"user": fixed["service_role"], "password": fixed["service_password"]})
    )
    runtime_role = postgres_harness.role_names["runtime"]
    with psycopg.connect(postgres_harness.dsns["admin"], autocommit=True) as admin:
        admin.execute(
            sql.SQL("GRANT {} TO {}").format(
                sql.Identifier(runtime_role), sql.Identifier(fixed["service_role"])
            )
        )
    try:
        engine = create_engine(sqlalchemy_url_from_dsn(service_dsn))
        gateway = PhotoLifecycleGateway(
            factory=sessionmaker(bind=engine, expire_on_commit=False),
            service_dsn=service_dsn,
            quarantine_root=_tmp_quarantine_root(),
            runtime_role=runtime_role,
            builder_role=postgres_harness.role_names["dev"],
        )
        with pytest.raises(RuntimeError, match="membership closure"):
            gateway.verify_service_authority()
        engine.dispose()
    finally:
        with psycopg.connect(postgres_harness.dsns["admin"], autocommit=True) as admin:
            admin.execute(
                sql.SQL("REVOKE {} FROM {}").format(
                    sql.Identifier(runtime_role), sql.Identifier(fixed["service_role"])
                )
            )


def test_gateway_startup_rejects_relation_ownership_drift(
    postgres_harness: PostgresHarness, phase6_review_schema: None
) -> None:
    import psycopg
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from itda.api.routes.photo import PhotoLifecycleGateway
    from itda.db.session import sqlalchemy_url_from_dsn
    from tests.integration.profile_release_test_support import ensure_photo_lifecycle_roles

    fixed = ensure_photo_lifecycle_roles(postgres_harness)
    admin_info = conninfo_to_dict(postgres_harness.dsns["admin"])
    service_dsn = make_conninfo(
        **(admin_info | {"user": fixed["service_role"], "password": fixed["service_password"]})
    )
    with psycopg.connect(postgres_harness.dsns["admin"], autocommit=True) as admin:
        admin.execute("ALTER TABLE dev_eval.photo_review_drafts OWNER TO CURRENT_USER")
    try:
        engine = create_engine(sqlalchemy_url_from_dsn(service_dsn))
        gateway = PhotoLifecycleGateway(
            factory=sessionmaker(bind=engine, expire_on_commit=False),
            service_dsn=service_dsn,
            quarantine_root=_tmp_quarantine_root(),
            runtime_role=postgres_harness.role_names["runtime"],
            builder_role=postgres_harness.role_names["dev"],
        )
        with pytest.raises(RuntimeError, match="lifecycle ownership"):
            gateway.verify_service_authority()
        engine.dispose()
    finally:
        with psycopg.connect(postgres_harness.dsns["admin"], autocommit=True) as admin:
            admin.execute(
                "ALTER TABLE dev_eval.photo_review_drafts OWNER TO itda_photo_write_authority"
            )


def test_gateway_startup_accepts_exact_service_identity(
    postgres_harness: PostgresHarness, phase6_review_schema: None
) -> None:
    """The fixed service DSN passes every identity and authority check."""

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from itda.api.routes.photo import PhotoLifecycleGateway
    from itda.db.session import sqlalchemy_url_from_dsn
    from tests.integration.profile_release_test_support import ensure_photo_lifecycle_roles

    fixed = ensure_photo_lifecycle_roles(postgres_harness)
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    admin_info = conninfo_to_dict(postgres_harness.dsns["admin"])
    service_dsn = make_conninfo(
        **(admin_info | {"user": fixed["service_role"], "password": fixed["service_password"]})
    )
    engine = create_engine(sqlalchemy_url_from_dsn(service_dsn))
    gateway = PhotoLifecycleGateway(
        factory=sessionmaker(bind=engine, expire_on_commit=False),
        service_dsn=service_dsn,
        quarantine_root=_tmp_quarantine_root(),
        runtime_role=postgres_harness.role_names["runtime"],
        builder_role=postgres_harness.role_names["dev"],
    )
    gateway.verify_service_authority()


def test_no_production_direct_lifecycle_writes_remain(
    postgres_harness: PostgresHarness, phase6_review_schema: None
) -> None:
    """No production module reads or writes lifecycle tables directly."""

    import inspect

    from itda.api.routes import photo as photo_routes
    from itda.db import photo_repositories
    from itda.photo import jobs as photo_jobs

    for module in (photo_routes, photo_repositories, photo_jobs):
        source = inspect.getsource(module)
        for forbidden in (
            "INSERT INTO dev_eval.photo_",
            "UPDATE dev_eval.photo_",
            "DELETE FROM dev_eval.photo_",
            "SELECT count(*) FROM dev_eval.photo_",
        ):
            assert forbidden not in source, (
                f"{module.__name__} must not touch lifecycle tables: {forbidden}"
            )
    deletion_source = inspect.getsource(
        __import__("itda.photo.deletion", fromlist=["_insert_ledger_row"])
    )
    assert "INSERT INTO dev_eval.photo_deletion_ledger" not in deletion_source
    assert "FROM dev_eval.photo_deletion_ledger" not in deletion_source
    assert "append_photo_deletion_ledger_v3" in deletion_source
    assert "finalize_photo_job_terminal_v3" in deletion_source
    assert "transition_photo_job_status_v2" not in deletion_source
    assert "list_photo_deletion_ledger_v3" in deletion_source
    # Repository reads go through the owner-scoped read projections only.
    repository_source = inspect.getsource(photo_repositories)
    for required in (
        "read_photo_job_v2",
        "list_photo_candidates_v2",
        "list_photo_confirmed_traits_v2",
        "read_photo_review_draft_v2",
        "read_photo_confirmation_receipt_v2",
    ):
        assert required in repository_source, (
            f"repository must use the owned read projection: {required}"
        )
