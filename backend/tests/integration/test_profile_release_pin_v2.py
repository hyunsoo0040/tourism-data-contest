"""Copy-once pin provenance across v1/v2 activation and exact rollback."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest
from alembic import command
from sqlalchemy import Engine

from itda.db.evaluation_repositories import EvaluationRepository
from itda.db.session import create_database_engine, create_session_factory
from tests.integration.test_profile_release import (
    ProfileReleaseConnections,
    _clear_profile_release_state_for_downgrade,
    _migration_config,
)
from tests.integration.test_profile_release import (
    profile_release_build_authority as _profile_release_build_authority,
)
from tests.integration.test_profile_release import (
    profile_release_connections as _profile_release_connections_fixture,  # noqa: F401
)
from tests.integration.test_profile_release_v2 import (
    _resolve_for_active_predecessor,
    _seed_active_predecessor,
)


@pytest.fixture
def profile_release_connections(
    request: pytest.FixtureRequest,
) -> ProfileReleaseConnections:
    return cast(
        ProfileReleaseConnections,
        request.getfixturevalue("_profile_release_connections_fixture"),
    )


@pytest.fixture(autouse=True)
def clean_profile_release_pin_v2_state(
    postgres_harness: object,
    profile_release_connections: ProfileReleaseConnections,
) -> Iterator[None]:
    config = _migration_config(postgres_harness, profile_release_connections.role_names)
    command.upgrade(config, "head")
    _clear_profile_release_state_for_downgrade(postgres_harness)
    try:
        yield
    finally:
        command.upgrade(config, "head")
        _clear_profile_release_state_for_downgrade(postgres_harness)


def _nonce(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _builder_repository(
    connections: ProfileReleaseConnections,
) -> tuple[EvaluationRepository, tuple[Engine, Engine]]:
    builder_engine = create_database_engine(connections.dsns["builder"])
    authority_engine = create_database_engine(connections.dsns["authority_service"])
    return (
        EvaluationRepository(
            create_session_factory(builder_engine),
            authority_connection_factory=create_session_factory(authority_engine),
        ),
        (builder_engine, authority_engine),
    )


def test_v1_v2_pins_are_copy_once_across_activation_and_exact_rollback(
    tmp_path: Path,
    postgres_harness: object,
    profile_release_connections: ProfileReleaseConnections,
) -> None:
    repository, engine, predecessor = _seed_active_predecessor(
        postgres_harness.dsns["admin"],
        profile_release_connections.dsns["builder"],
        profile_release_connections.dsns["authority_service"],
        build_nonce="pin-v2-predecessor-build",
        activate_nonce="pin-v2-predecessor-activate",
    )
    successor = _resolve_for_active_predecessor(tmp_path, repository)
    builder_repository, builder_engines = _builder_repository(profile_release_connections)
    predecessor_sha256 = cast(str, predecessor.release_sha256)
    successor_sha256 = cast(str, successor.release_sha256)
    approver = "synthetic-v2-approver"
    try:
        before_session = repository.pin_profile_release_session("pin-v2-session-before")
        before_result = repository.pin_profile_release_result("pin-v2-result-before")
        assert before_session.release_sha256 == predecessor_sha256
        assert before_result.release_sha256 == predecessor_sha256

        builder_repository.build_profile_release(
            _profile_release_build_authority(builder_repository, successor),
            authenticated_principal=successor.builder_principal,
            reconciliation_nonce=_nonce("pin-v2-successor-build"),
        )
        repository.approve_profile_release(
            successor_sha256,
            authenticated_principal=approver,
        )
        repository.activate_profile_release(
            successor_sha256,
            expected_current=predecessor_sha256,
            authenticated_principal=approver,
            nonce=_nonce("pin-v2-successor-activate"),
        )
        after_session = repository.pin_profile_release_session("pin-v2-session-after")
        after_result = repository.pin_profile_release_result("pin-v2-result-after")
        assert after_session.release_sha256 == successor_sha256
        assert after_result.release_sha256 == successor_sha256
        assert repository.pin_profile_release_session("pin-v2-session-before") == before_session
        assert repository.pin_profile_release_result("pin-v2-result-before") == before_result

        with postgres_harness.connect("admin", autocommit=True) as connection:
            assert connection.execute(
                "SELECT dev_eval.validate_active_profile_release_for_pin_dispatch_v1(%s, "
                "(SELECT receipt_sha256 FROM dev_eval.profile_release_active_pointer "
                "WHERE slot = 'DEV'))",
                (successor_sha256,),
            ).fetchone() == (True,)

        repository.rollback_profile_release(
            predecessor_sha256,
            expected_current=successor_sha256,
            authenticated_principal=approver,
            reason="copy-once pin rollback verification",
            nonce=_nonce("pin-v2-successor-rollback"),
        )
        rollback_session = repository.pin_profile_release_session("pin-v2-session-rollback")
        rollback_result = repository.pin_profile_release_result("pin-v2-result-rollback")
        assert rollback_session.release_sha256 == predecessor_sha256
        assert rollback_result.release_sha256 == predecessor_sha256
        assert repository.pin_profile_release_session("pin-v2-session-after") == after_session
        assert repository.pin_profile_release_result("pin-v2-result-after") == after_result

        assert (
            repository.get_profile_release_session_pin("pin-v2-session-before").release_sha256
            == predecessor_sha256
        )
        assert (
            repository.get_profile_release_session_pin("pin-v2-session-after").release_sha256
            == successor_sha256
        )
    finally:
        for builder_engine in builder_engines:
            builder_engine.dispose()
        engine.dispose()


def test_v2_pin_validation_rejects_malformed_active_payload(
    tmp_path: Path,
    postgres_harness: object,
    profile_release_connections: ProfileReleaseConnections,
) -> None:
    repository, engine, predecessor = _seed_active_predecessor(
        postgres_harness.dsns["admin"],
        profile_release_connections.dsns["builder"],
        profile_release_connections.dsns["authority_service"],
        build_nonce="pin-v2-malformed-predecessor-build",
        activate_nonce="pin-v2-malformed-predecessor-activate",
    )
    successor = _resolve_for_active_predecessor(tmp_path, repository)
    builder_repository, builder_engines = _builder_repository(profile_release_connections)
    successor_sha256 = cast(str, successor.release_sha256)
    try:
        builder_repository.build_profile_release(
            _profile_release_build_authority(builder_repository, successor),
            authenticated_principal=successor.builder_principal,
            reconciliation_nonce=_nonce("pin-v2-malformed-successor-build"),
        )
        repository.approve_profile_release(
            successor_sha256,
            authenticated_principal="synthetic-v2-approver",
        )
        repository.activate_profile_release(
            successor_sha256,
            expected_current=cast(str, predecessor.release_sha256),
            authenticated_principal="synthetic-v2-approver",
            nonce=_nonce("pin-v2-malformed-successor-activate"),
        )
        with postgres_harness.connect("admin") as connection:
            connection.execute(
                "ALTER TABLE dev_eval.profile_releases DISABLE TRIGGER "
                "reject_profile_releases_mutation_v1"
            )
            connection.execute(
                "UPDATE dev_eval.profile_releases SET payload = jsonb_set("
                "payload, '{lineage,lineage_sha256}', to_jsonb(%s::text)) "
                "WHERE release_sha256 = %s",
                ("0" * 64, successor_sha256),
            )
            receipt_sha256 = connection.execute(
                "SELECT receipt_sha256 FROM dev_eval.profile_release_active_pointer "
                "WHERE slot = 'DEV'"
            ).fetchone()[0]
            assert connection.execute(
                "SELECT dev_eval.validate_active_profile_release_for_pin_dispatch_v1(%s, %s)",
                (successor_sha256, receipt_sha256),
            ).fetchone() == (False,)
            connection.rollback()
    finally:
        for builder_engine in builder_engines:
            builder_engine.dispose()
        engine.dispose()
