"""Local-only Phase 4 demo release lifecycle integration contracts."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Literal, cast

import pytest

from itda.cli.run_phase4_demo import (
    main as phase4_demo_main,
)
from itda.db.phase4_demo_release import (
    LOCAL_APPROVAL_MARKER,
    LOCAL_SQLITE_MARKER,
    Phase4DemoReleaseError,
    Phase4DemoReleaseRepository,
    _publish_final_receipt,
    initialize_demo_release,
    verify_demo_release,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ACTUAL_CATALOG_AUDIT = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/release/final-audit/canonical-36.json"
)
ACTUAL_DEV_SQLITE = (
    REPOSITORY_ROOT
    / "artifacts/restricted/catalog/v2/sqlite/releases"
    / "e45fae2e591542c1ecd8cc041ce4d2af863944f57be593ad38bfc196cf289ed0"
    / "evaluation-authority.sqlite3"
)
ACTUAL_SNAPSHOT_ROOT = REPOSITORY_ROOT / "artifacts/restricted/catalog/v1/collection/snapshots"
ACTUAL_OPTIONAL_MEDIA = (
    REPOSITORY_ROOT
    / "artifacts/catalog/optional-media-v2/policy"
    / "573e21213f7c0d157e33c7a510b9bcdb612dd517dfc70ba506ef7281ca0e9243"
    / "projected-candidates.json"
)


@pytest.fixture
def demo_inputs(tmp_path: Path) -> dict[str, Path]:
    public_root = tmp_path / "artifacts/public/catalog/v2"
    artifact_root = tmp_path / "artifacts/restricted/catalog/v2/phase4-demo"
    public_root.mkdir(parents=True)
    artifact_root.parent.mkdir(parents=True)
    materialization = public_root / "phase4-demo-materialization-receipt.json"
    prediction = public_root / "phase4-demo-prediction-receipt.json"
    terminal = public_root / "phase4-demo-terminal-receipt.json"
    assert (
        phase4_demo_main(
            [
                "materialize",
                "--artifact-root",
                str(artifact_root),
                "--receipt-output",
                str(materialization),
            ]
        )
        == 0
    )
    assert (
        phase4_demo_main(
            [
                "observe",
                "--materialization-receipt",
                str(materialization),
                "--artifact-root",
                str(artifact_root),
                "--provider-mode",
                "auto",
                "--replay-fixture",
                str(tmp_path / "unused-replay.json"),
                "--receipt-output",
                str(prediction),
            ]
        )
        == 0
    )
    assert (
        phase4_demo_main(
            [
                "prepare-evaluation",
                "--materialization-receipt",
                str(materialization),
                "--prediction-receipt",
                str(prediction),
                "--artifact-root",
                str(artifact_root),
            ]
        )
        == 0
    )
    assert (
        phase4_demo_main(
            [
                "finalize",
                "--materialization-receipt",
                str(materialization),
                "--prediction-receipt",
                str(prediction),
                "--artifact-root",
                str(artifact_root),
                "--receipt-output",
                str(terminal),
            ]
        )
        == 0
    )
    return {
        "terminal_receipt": terminal,
        "artifact_root": artifact_root,
    }


def _repository(inputs: dict[str, Path]) -> Phase4DemoReleaseRepository:
    return Phase4DemoReleaseRepository.from_terminal_receipt(
        terminal_receipt_path=inputs["terminal_receipt"],
        artifact_root=inputs["artifact_root"],
    )


def _all_receipts(repository: Phase4DemoReleaseRepository) -> list[dict[str, object]]:
    with sqlite3.connect(repository.database_path) as connection:
        rows = connection.execute(
            "SELECT receipt_json FROM receipts ORDER BY receipt_ordinal"
        ).fetchall()
    return [json.loads(row[0]) for row in rows]


def _lifecycle_counts(repository: Phase4DemoReleaseRepository) -> tuple[int, int, int]:
    with sqlite3.connect(repository.database_path) as connection:
        approval_count = connection.execute("SELECT count(*) FROM approvals").fetchone()[0]
        transition_count = connection.execute("SELECT count(*) FROM transition_history").fetchone()[
            0
        ]
        receipt_count = connection.execute("SELECT count(*) FROM receipts").fetchone()[0]
    return approval_count, transition_count, receipt_count


def test_initialize_accepts_exact_upstream_without_local_markers(
    demo_inputs: dict[str, Path],
) -> None:
    upstream = json.loads(demo_inputs["terminal_receipt"].read_bytes())
    assert LOCAL_SQLITE_MARKER not in upstream.values()
    assert LOCAL_APPROVAL_MARKER not in upstream.values()

    result = initialize_demo_release(
        terminal_receipt_path=demo_inputs["terminal_receipt"],
        artifact_root=demo_inputs["artifact_root"],
    )
    repository = _repository(demo_inputs)
    status = repository.status(create_receipt=False)

    assert result["disposition"] == "CREATED"
    assert status["source_truth"] == "LOCAL_COLLECTION_AUTHORITY_PARTIAL"
    assert status["profile_truth"] == "SOURCE_EVIDENCE_ONLY"
    assert status["profile_score_truth"] == "NO_LOCAL_PROFILE_SCORES"
    assert status["image_truth"] == "NO_IMAGE_TEXT_ODII_ONLY"
    assert status["provider_mode"] == "NO_PROVIDER_NO_IMAGE"
    assert status["terminal_decision"] == "NO_IMAGE_TEXT_ODII_ONLY"
    assert status["active_release_sha256"] == status["predecessor_sha256"]
    assert status["successor_state"] == "BUILT_UNAPPROVED"
    assert status["generation"] == 0
    assert status["upstream_terminal_receipt_sha256"] == upstream["receipt_sha256"]
    assert status["terminal_report_sha256"] == upstream["terminal_report_sha256"]
    assert status["predecessor_sha256"] != status["successor_sha256"]


def test_initialize_uses_private_full_synchronous_foreign_key_database(
    demo_inputs: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    initialize_demo_release(
        terminal_receipt_path=demo_inputs["terminal_receipt"],
        artifact_root=demo_inputs["artifact_root"],
    )
    repository = _repository(demo_inputs)
    expected_parent = (
        demo_inputs["artifact_root"]
        / json.loads(demo_inputs["terminal_receipt"].read_bytes())["manifest_sha256"]
        / "release"
    )
    assert repository.database_path == expected_parent / "phase4-demo-release.sqlite3"
    assert repository.database_path.stat().st_mode & 0o777 == 0o600
    assert repository.database_path.parent.stat().st_mode & 0o777 == 0o700
    assert not any(
        repository.database_path.with_name(repository.database_path.name + suffix).exists()
        for suffix in ("-journal", "-wal", "-shm")
    )
    with sqlite3.connect(repository.database_path) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("PRAGMA journal_mode").fetchone() == ("delete",)
        assert connection.execute("PRAGMA synchronous").fetchone() == (2,)

    with pytest.raises(Phase4DemoReleaseError, match="production|network|DSN"):
        Phase4DemoReleaseRepository(
            database_path=Path("postgresql://production/profile-release"),
            run_root=demo_inputs["artifact_root"],
        )
    monkeypatch.setenv("ITDA_PHASE3_DATABASE_URL", "postgresql://production.invalid/db")
    with pytest.raises(Phase4DemoReleaseError, match="production capability"):
        initialize_demo_release(
            terminal_receipt_path=demo_inputs["terminal_receipt"],
            artifact_root=demo_inputs["artifact_root"],
        )


def test_initialize_receipts_are_dual_marked_and_immutable(
    demo_inputs: dict[str, Path],
) -> None:
    initialize_demo_release(
        terminal_receipt_path=demo_inputs["terminal_receipt"],
        artifact_root=demo_inputs["artifact_root"],
    )
    repository = _repository(demo_inputs)
    receipts = _all_receipts(repository)
    assert {row["receipt_type"] for row in receipts} == {"BUILD", "PIN", "STATUS"}
    assert sum(row["receipt_type"] == "PIN" for row in receipts) == 2
    for receipt in receipts:
        assert receipt["local_storage_scope"] == LOCAL_SQLITE_MARKER
        assert receipt["approval_authority"] == LOCAL_APPROVAL_MARKER
        repository.validate_local_receipt(receipt)
        for field in ("local_storage_scope", "approval_authority"):
            tampered = dict(receipt)
            tampered[field] = "PRODUCTION"
            with pytest.raises(Phase4DemoReleaseError, match="local marker"):
                repository.validate_local_receipt(tampered)

    with sqlite3.connect(repository.database_path) as connection:
        for statement in (
            "UPDATE releases SET payload_json = payload_json",
            "DELETE FROM receipts",
            "UPDATE session_pins SET release_sha256 = release_sha256",
            "UPDATE result_pins SET release_sha256 = release_sha256",
            "UPDATE active_pointer SET generation = generation + 1",
        ):
            with pytest.raises(sqlite3.DatabaseError):
                connection.execute(statement)


def test_initialize_recovers_identical_and_rejects_parent_or_sidecar_drift(
    demo_inputs: dict[str, Path],
) -> None:
    first = initialize_demo_release(
        terminal_receipt_path=demo_inputs["terminal_receipt"],
        artifact_root=demo_inputs["artifact_root"],
    )
    repository = _repository(demo_inputs)
    before = repository.database_path.read_bytes()
    second = initialize_demo_release(
        terminal_receipt_path=demo_inputs["terminal_receipt"],
        artifact_root=demo_inputs["artifact_root"],
    )
    assert second["disposition"] == "ALREADY_INITIALIZED_VERIFIED"
    assert second["database_sha256"] == first["database_sha256"]
    assert repository.database_path.read_bytes() == before

    original = demo_inputs["terminal_receipt"].read_bytes()
    payload = json.loads(original)
    payload["receipt_sha256"] = "0" * 64
    demo_inputs["terminal_receipt"].write_bytes(canonical_json_bytes(payload))
    with pytest.raises(Phase4DemoReleaseError, match="upstream terminal"):
        initialize_demo_release(
            terminal_receipt_path=demo_inputs["terminal_receipt"],
            artifact_root=demo_inputs["artifact_root"],
        )
    demo_inputs["terminal_receipt"].write_bytes(original)

    sidecar = repository.database_path.with_name(repository.database_path.name + "-wal")
    sidecar.write_bytes(b"do-not-delete")
    with pytest.raises(Phase4DemoReleaseError, match="sidecar"):
        initialize_demo_release(
            terminal_receipt_path=demo_inputs["terminal_receipt"],
            artifact_root=demo_inputs["artifact_root"],
        )
    assert sidecar.read_bytes() == b"do-not-delete"


def test_initialize_creates_predecessor_era_copy_once_pins(
    demo_inputs: dict[str, Path],
) -> None:
    initialize_demo_release(
        terminal_receipt_path=demo_inputs["terminal_receipt"],
        artifact_root=demo_inputs["artifact_root"],
    )
    repository = _repository(demo_inputs)
    status = repository.status(create_receipt=False)
    with sqlite3.connect(repository.database_path) as connection:
        releases = connection.execute(
            "SELECT release_role, initial_state, release_sha256 FROM releases ORDER BY release_role"
        ).fetchall()
        session = connection.execute(
            "SELECT release_sha256, generation FROM session_pins"
        ).fetchone()
        result = connection.execute("SELECT release_sha256, generation FROM result_pins").fetchone()
    assert releases == [
        ("SOURCE_EVIDENCE_PREDECESSOR", "ACTIVE", status["predecessor_sha256"]),
        ("TERMINAL_EVIDENCE_SUCCESSOR", "BUILT_UNAPPROVED", status["successor_sha256"]),
    ]
    assert session == (status["predecessor_sha256"], 0)
    assert result == (status["predecessor_sha256"], 0)


def test_approve_exact_successor_without_moving_active_pointer(
    demo_inputs: dict[str, Path],
) -> None:
    initialize_demo_release(
        terminal_receipt_path=demo_inputs["terminal_receipt"],
        artifact_root=demo_inputs["artifact_root"],
    )
    repository = _repository(demo_inputs)
    before = repository.status(create_receipt=False)

    receipt = repository.approve_release(str(before["successor_sha256"]))
    after = repository.status(create_receipt=False)

    assert receipt["receipt_type"] == "APPROVAL"
    assert receipt["release_sha256"] == before["successor_sha256"]
    assert after["active_release_sha256"] == before["predecessor_sha256"]
    assert after["generation"] == 0
    assert after["successor_state"] == "APPROVED_INACTIVE"
    repository.validate_local_receipt(receipt)

    counts = _lifecycle_counts(repository)
    with pytest.raises(Phase4DemoReleaseError, match="replay"):
        repository.approve_release(str(before["successor_sha256"]))
    assert _lifecycle_counts(repository) == counts


def test_activate_rejects_stale_sibling_and_replay_then_commits_exact_successor(
    demo_inputs: dict[str, Path],
) -> None:
    initialize_demo_release(
        terminal_receipt_path=demo_inputs["terminal_receipt"],
        artifact_root=demo_inputs["artifact_root"],
    )
    repository = _repository(demo_inputs)
    initial = repository.status(create_receipt=False)
    predecessor = str(initial["predecessor_sha256"])
    successor = str(initial["successor_sha256"])
    repository.approve_release(successor)

    counts = _lifecycle_counts(repository)
    with pytest.raises(Phase4DemoReleaseError, match="stale"):
        repository.activate_release(
            successor,
            expected_current=predecessor,
            expected_generation=9,
        )
    with pytest.raises(Phase4DemoReleaseError, match="exact successor"):
        repository.activate_release(
            predecessor,
            expected_current=predecessor,
            expected_generation=0,
        )
    assert _lifecycle_counts(repository) == counts

    receipt = repository.activate_release(
        successor,
        expected_current=predecessor,
        expected_generation=0,
    )
    active = repository.status(create_receipt=False)
    assert receipt["receipt_type"] == "ACTIVATION"
    assert active["active_release_sha256"] == successor
    assert active["generation"] == 1

    counts = _lifecycle_counts(repository)
    with pytest.raises(Phase4DemoReleaseError, match="stale|replay"):
        repository.activate_release(
            successor,
            expected_current=predecessor,
            expected_generation=0,
        )
    assert _lifecycle_counts(repository) == counts


def test_rollback_and_reactivate_preserve_immutable_transition_history(
    demo_inputs: dict[str, Path],
) -> None:
    initialize_demo_release(
        terminal_receipt_path=demo_inputs["terminal_receipt"],
        artifact_root=demo_inputs["artifact_root"],
    )
    repository = _repository(demo_inputs)
    initial = repository.status(create_receipt=False)
    predecessor = str(initial["predecessor_sha256"])
    successor = str(initial["successor_sha256"])
    repository.approve_release(successor)
    repository.activate_release(
        successor,
        expected_current=predecessor,
        expected_generation=0,
    )

    rollback = repository.rollback_release(
        predecessor,
        expected_current=successor,
        expected_generation=1,
        reason="contest demo rollback verification",
    )
    rolled_back = repository.status(create_receipt=False)
    assert rollback["receipt_type"] == "ROLLBACK"
    assert rollback["reason_sha256"]
    assert rolled_back["active_release_sha256"] == predecessor
    assert rolled_back["generation"] == 2

    reactivate = repository.reactivate_release(
        successor,
        expected_current=predecessor,
        expected_generation=2,
    )
    final = repository.status(create_receipt=False)
    assert reactivate["receipt_type"] == "REACTIVATION"
    assert final["active_release_sha256"] == successor
    assert final["generation"] == 3

    with sqlite3.connect(repository.database_path) as connection:
        rows = connection.execute(
            "SELECT action, target_release_sha256, previous_release_sha256, "
            "expected_generation, new_generation, reason_sha256 "
            "FROM transition_history ORDER BY new_generation"
        ).fetchall()
        assert rows == [
            ("ACTIVATE", successor, predecessor, 0, 1, None),
            ("ROLLBACK", predecessor, successor, 1, 2, rollback["reason_sha256"]),
            ("REACTIVATE", successor, predecessor, 2, 3, None),
        ]
        with pytest.raises(sqlite3.DatabaseError):
            connection.execute("UPDATE transition_history SET action = action")


def test_replay_failures_are_atomic_and_every_lifecycle_receipt_is_dual_marked(
    demo_inputs: dict[str, Path],
) -> None:
    initialize_demo_release(
        terminal_receipt_path=demo_inputs["terminal_receipt"],
        artifact_root=demo_inputs["artifact_root"],
    )
    repository = _repository(demo_inputs)
    result = repository.exercise_lifecycle(final_state="successor")
    assert result["active_release_sha256"] == result["successor_sha256"]
    assert result["generation"] == 3

    lifecycle_types = {"APPROVAL", "ACTIVATION", "ROLLBACK", "REACTIVATION", "STATUS"}
    lifecycle_receipts = [
        receipt
        for receipt in _all_receipts(repository)
        if receipt["receipt_type"] in lifecycle_types
    ]
    assert lifecycle_types <= {receipt["receipt_type"] for receipt in lifecycle_receipts}
    for receipt in lifecycle_receipts:
        assert receipt["local_storage_scope"] == LOCAL_SQLITE_MARKER
        assert receipt["approval_authority"] == LOCAL_APPROVAL_MARKER
        repository.validate_local_receipt(receipt)
        tampered = dict(receipt)
        tampered["receipt_type"] = "ACTIVATION"
        if tampered == receipt:
            tampered["receipt_type"] = "ROLLBACK"
        with pytest.raises(Phase4DemoReleaseError, match="digest"):
            repository.validate_local_receipt(tampered)

    counts = _lifecycle_counts(repository)
    with pytest.raises(Phase4DemoReleaseError, match="replay|stale"):
        repository.reactivate_release(
            str(result["successor_sha256"]),
            expected_current=str(result["predecessor_sha256"]),
            expected_generation=2,
        )
    assert _lifecycle_counts(repository) == counts


def test_lifecycle_era_pins_remain_bound_to_their_creation_release(
    demo_inputs: dict[str, Path],
) -> None:
    initialize_demo_release(
        terminal_receipt_path=demo_inputs["terminal_receipt"],
        artifact_root=demo_inputs["artifact_root"],
    )
    repository = _repository(demo_inputs)
    lifecycle = repository.exercise_lifecycle(final_state="successor")
    repository.ensure_lifecycle_pins()

    with sqlite3.connect(repository.database_path) as connection:
        rows = connection.execute(
            "SELECT receipts.receipt_json FROM receipts "
            "WHERE receipts.receipt_type = 'PIN' ORDER BY receipts.receipt_ordinal"
        ).fetchall()
    pins = [json.loads(row[0]) for row in rows]
    expected = {
        "PREDECESSOR": (lifecycle["predecessor_sha256"], 0),
        "SUCCESSOR": (lifecycle["successor_sha256"], 1),
        "POST_ROLLBACK": (lifecycle["predecessor_sha256"], 2),
        "FINAL": (lifecycle["successor_sha256"], 3),
    }
    assert len(pins) == 8
    for era, release_and_generation in expected.items():
        era_pins = [receipt for receipt in pins if receipt["era"] == era]
        assert {receipt["pin_kind"] for receipt in era_pins} == {"SESSION", "RESULT"}
        assert {(receipt["release_sha256"], receipt["generation"]) for receipt in era_pins} == {
            release_and_generation
        }


def test_copy_once_pin_reuse_with_another_release_fails_atomically(
    demo_inputs: dict[str, Path],
) -> None:
    initialize_demo_release(
        terminal_receipt_path=demo_inputs["terminal_receipt"],
        artifact_root=demo_inputs["artifact_root"],
    )
    repository = _repository(demo_inputs)
    initial = repository.status(create_receipt=False)
    repository.pin_active(kind="SESSION", owner_ref="copy-once-session", era="PROBE")
    repository.pin_active(kind="RESULT", owner_ref="copy-once-result", era="PROBE")
    repository.approve_release(str(initial["successor_sha256"]))
    repository.activate_release(
        str(initial["successor_sha256"]),
        expected_current=str(initial["predecessor_sha256"]),
        expected_generation=0,
    )

    counts = _lifecycle_counts(repository)
    pin_cases: tuple[tuple[Literal["SESSION", "RESULT"], str], ...] = (
        ("SESSION", "copy-once-session"),
        ("RESULT", "copy-once-result"),
    )
    for kind, owner_ref in pin_cases:
        with pytest.raises(Phase4DemoReleaseError, match="copy-once"):
            repository.pin_active(kind=kind, owner_ref=owner_ref, era="PROBE")
    assert _lifecycle_counts(repository) == counts


@pytest.mark.parametrize("tamper", ["release_payload", "active_generation"])
def test_verify_rejects_release_or_active_generation_corruption(
    demo_inputs: dict[str, Path], tmp_path: Path, tamper: str
) -> None:
    initialize_demo_release(
        terminal_receipt_path=demo_inputs["terminal_receipt"],
        artifact_root=demo_inputs["artifact_root"],
    )
    repository = _repository(demo_inputs)
    repository.exercise_lifecycle(final_state="successor")
    repository.ensure_lifecycle_pins()
    with sqlite3.connect(repository.database_path) as connection:
        if tamper == "release_payload":
            connection.execute("DROP TRIGGER releases_no_update")
            connection.execute(
                "UPDATE releases SET payload_json = json_set(payload_json, '$.tampered', 1) "
                "WHERE release_role = 'TERMINAL_EVIDENCE_SUCCESSOR'"
            )
        else:
            connection.execute("DROP TRIGGER pointer_guard_update")
            connection.execute("UPDATE active_pointer SET generation = 4")
        connection.commit()

    with pytest.raises(Phase4DemoReleaseError, match="drift|generation|lifecycle"):
        verify_demo_release(
            terminal_receipt_path=demo_inputs["terminal_receipt"],
            artifact_root=demo_inputs["artifact_root"],
            receipt_output=tmp_path / "receipt.json",
        )


def test_initialize_reconciles_receipts_after_post_commit_publication_failure(
    demo_inputs: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_publish = Phase4DemoReleaseRepository._publish_receipts

    def _fail_between_publications(
        repository: Phase4DemoReleaseRepository,
        receipts: list[dict[str, object]],
    ) -> None:
        original_publish(repository, receipts[:1])
        raise OSError("synthetic publication failure after SQLite commit")

    monkeypatch.setattr(
        Phase4DemoReleaseRepository,
        "_publish_receipts",
        _fail_between_publications,
    )
    with pytest.raises(OSError, match="after SQLite commit"):
        initialize_demo_release(
            terminal_receipt_path=demo_inputs["terminal_receipt"],
            artifact_root=demo_inputs["artifact_root"],
        )

    monkeypatch.setattr(
        Phase4DemoReleaseRepository,
        "_publish_receipts",
        original_publish,
    )
    recovered = initialize_demo_release(
        terminal_receipt_path=demo_inputs["terminal_receipt"],
        artifact_root=demo_inputs["artifact_root"],
    )

    assert recovered["disposition"] == "ALREADY_INITIALIZED_VERIFIED"


@pytest.mark.parametrize("failed_publication", (1, 2, 3, 4))
def test_lifecycle_resumes_after_each_post_commit_publication_failure(
    demo_inputs: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
    failed_publication: int,
) -> None:
    initialize_demo_release(
        terminal_receipt_path=demo_inputs["terminal_receipt"],
        artifact_root=demo_inputs["artifact_root"],
    )
    repository = _repository(demo_inputs)
    original_publish = repository._publish_receipts
    publication_count = 0

    def _fail_selected_publication(receipts: list[dict[str, object]]) -> None:
        nonlocal publication_count
        publication_count += 1
        if publication_count == failed_publication:
            raise OSError("synthetic lifecycle publication failure after commit")
        original_publish(receipts)

    monkeypatch.setattr(repository, "_publish_receipts", _fail_selected_publication)
    with pytest.raises(OSError, match="publication failure"):
        repository.exercise_lifecycle(final_state="successor")
    monkeypatch.setattr(repository, "_publish_receipts", original_publish)

    recovered = repository.exercise_lifecycle(final_state="successor")

    assert recovered["successor_state"] == "ACTIVE"
    assert recovered["active_release_sha256"] == recovered["successor_sha256"]
    assert recovered["generation"] == 3
    assert recovered["transition_count"] == 3
    with sqlite3.connect(repository.database_path) as connection:
        committed_count = connection.execute("SELECT count(*) FROM receipts").fetchone()[0]
    published_count = len(list((repository.database_path.parent / "receipts").glob("*.json")))
    assert published_count == committed_count


def test_ordinary_status_read_does_not_change_final_receipt_inventory(
    demo_inputs: dict[str, Path],
    tmp_path: Path,
) -> None:
    initialize_demo_release(
        terminal_receipt_path=demo_inputs["terminal_receipt"],
        artifact_root=demo_inputs["artifact_root"],
    )
    repository = _repository(demo_inputs)
    before = _lifecycle_counts(repository)

    status = repository.status()

    assert status["generation"] == 0
    assert "status_receipt_sha256" not in status
    assert _lifecycle_counts(repository) == before
    repository.exercise_lifecycle(final_state="successor")
    verified = verify_demo_release(
        terminal_receipt_path=demo_inputs["terminal_receipt"],
        artifact_root=demo_inputs["artifact_root"],
        receipt_output=tmp_path / "status-read-release-receipt.json",
    )
    receipt_counts = cast(dict[str, int], verified["receipt_type_counts"])
    assert receipt_counts["STATUS"] == 8


def test_verification_rejects_concurrent_status_writer_snapshot_mix(
    demo_inputs: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    initialize_demo_release(
        terminal_receipt_path=demo_inputs["terminal_receipt"],
        artifact_root=demo_inputs["artifact_root"],
    )
    repository = _repository(demo_inputs)
    original_verify = Phase4DemoReleaseRepository._verify_private_receipts
    writer_errors: list[BaseException] = []

    def _verify_while_writer_waits(current: Phase4DemoReleaseRepository) -> None:
        def _write_status() -> None:
            try:
                repository.status(create_receipt=True)
            except BaseException as exc:  # noqa: BLE001 - capture thread evidence
                writer_errors.append(exc)

        writer = threading.Thread(target=_write_status)
        writer.start()
        writer.join(timeout=3.0)
        assert not writer.is_alive()
        original_verify(current)

    monkeypatch.setattr(
        Phase4DemoReleaseRepository,
        "_verify_private_receipts",
        _verify_while_writer_waits,
    )

    recovered = initialize_demo_release(
        terminal_receipt_path=demo_inputs["terminal_receipt"],
        artifact_root=demo_inputs["artifact_root"],
    )

    assert recovered["disposition"] == "ALREADY_INITIALIZED_VERIFIED"
    assert len(writer_errors) == 1
    assert isinstance(writer_errors[0], sqlite3.OperationalError)
    assert "locked" in str(writer_errors[0]).casefold()


def test_verify_publishes_digest_only_final_receipt_with_all_local_parents(
    demo_inputs: dict[str, Path], tmp_path: Path
) -> None:
    initialize_demo_release(
        terminal_receipt_path=demo_inputs["terminal_receipt"],
        artifact_root=demo_inputs["artifact_root"],
    )
    repository = _repository(demo_inputs)
    repository.exercise_lifecycle(final_state="successor")
    output = tmp_path / "phase4-demo-release-receipt.json"

    result = verify_demo_release(
        terminal_receipt_path=demo_inputs["terminal_receipt"],
        artifact_root=demo_inputs["artifact_root"],
        receipt_output=output,
    )
    payload = json.loads(output.read_bytes())

    assert result == payload
    assert output.read_bytes() == canonical_json_bytes(payload)
    assert payload["schema_version"] == "itda.phase4-demo-release-final-receipt.v1"
    assert payload["local_storage_scope"] == LOCAL_SQLITE_MARKER
    assert payload["approval_authority"] == LOCAL_APPROVAL_MARKER
    assert payload["production_mutation"] == "NO_PRODUCTION_MUTATION"
    assert payload["active_release_sha256"] == payload["successor_sha256"]
    assert payload["generation"] == 3
    assert payload["profile_truth"] == "SOURCE_EVIDENCE_ONLY"
    assert payload["profile_score_truth"] == "NO_LOCAL_PROFILE_SCORES"
    assert payload["session_pin_count"] == payload["result_pin_count"] == 4
    assert payload["foreign_key_check_count"] == 0
    assert payload["sqlite_sidecar_count"] == 0
    assert payload["receipt_type_counts"] == {
        "ACTIVATION": 1,
        "APPROVAL": 1,
        "BUILD": 1,
        "PIN": 8,
        "REACTIVATION": 1,
        "ROLLBACK": 1,
        "STATUS": 8,
    }
    repository.validate_local_receipt(payload)
    serialized = output.read_text(encoding="utf-8").casefold()
    for forbidden in (
        "artifact_root",
        "database_path",
        "owner_ref",
        "payload_json",
        "place_ref",
        "raw_image",
        "service_key",
        "postgresql://",
    ):
        assert forbidden not in serialized

    receipts = _all_receipts(repository)
    assert len(receipts) == payload["receipt_count"]
    assert {receipt["receipt_type"] for receipt in receipts} == set(payload["receipt_type_counts"])
    for receipt in receipts:
        repository.validate_local_receipt(receipt)
    before = output.read_bytes()
    assert (
        verify_demo_release(
            terminal_receipt_path=demo_inputs["terminal_receipt"],
            artifact_root=demo_inputs["artifact_root"],
            receipt_output=output,
        )
        == payload
    )
    assert output.read_bytes() == before


def test_final_receipt_recovers_a_truncated_prior_publication(
    demo_inputs: dict[str, Path], tmp_path: Path
) -> None:
    initialize_demo_release(
        terminal_receipt_path=demo_inputs["terminal_receipt"],
        artifact_root=demo_inputs["artifact_root"],
    )
    _repository(demo_inputs).exercise_lifecycle(final_state="successor")
    output = tmp_path / "phase4-demo-release-receipt.json"
    expected = verify_demo_release(
        terminal_receipt_path=demo_inputs["terminal_receipt"],
        artifact_root=demo_inputs["artifact_root"],
        receipt_output=output,
    )
    output.write_bytes(b"{")

    recovered = verify_demo_release(
        terminal_receipt_path=demo_inputs["terminal_receipt"],
        artifact_root=demo_inputs["artifact_root"],
        receipt_output=output,
    )

    assert recovered == expected
    assert output.read_bytes() == canonical_json_bytes(expected)
    quarantined = tuple(tmp_path.glob(".phase4-demo-release-receipt.json.incomplete-*"))
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == b"{"


def test_final_receipt_never_replaces_a_different_digest_valid_receipt(
    tmp_path: Path,
) -> None:
    output = tmp_path / "phase4-demo-release-receipt.json"
    expected: dict[str, object] = {
        "schema_version": "itda.phase4-demo-release-final-receipt.v1",
        "upstream_terminal_receipt_sha256": "1" * 64,
        "terminal_report_sha256": "2" * 64,
        "manifest_sha256": "3" * 64,
        "predecessor_sha256": "4" * 64,
        "successor_sha256": "5" * 64,
        "active_release_sha256": "5" * 64,
        "generation": 3,
        "database_sha256": "6" * 64,
        "sqlite_schema_version": "phase4-demo-v1",
        "sqlite_user_version": 1,
        "integrity_check": "ok",
        "foreign_key_check_count": 0,
        "sqlite_sidecar_count": 0,
        "receipt_count": 0,
        "receipt_type_counts": {},
        "receipt_inventory_sha256": "7" * 64,
        "session_pin_count": 0,
        "result_pin_count": 0,
        "pin_inventory_sha256": "8" * 64,
        "source_truth": "LOCAL_COLLECTION_AUTHORITY_PARTIAL",
        "profile_truth": "SOURCE_EVIDENCE_ONLY",
        "profile_score_truth": "NO_LOCAL_PROFILE_SCORES",
        "image_truth": "NO_LOCAL_IMAGES",
        "provider_mode": "NO_PROVIDER_NO_IMAGE",
        "terminal_decision": "NO_IMAGE_TEXT_ODII_ONLY",
        "local_storage_scope": LOCAL_SQLITE_MARKER,
        "approval_authority": LOCAL_APPROVAL_MARKER,
        "production_mutation": "NO_PRODUCTION_MUTATION",
    }
    expected["receipt_sha256"] = canonical_sha256(expected)
    _publish_final_receipt(output, expected)
    conflicting = {**expected, "production_mutation": "X"}
    conflicting["receipt_sha256"] = canonical_sha256(
        {key: value for key, value in conflicting.items() if key != "receipt_sha256"}
    )
    conflicting_bytes = canonical_json_bytes(conflicting)
    assert len(conflicting_bytes) < len(canonical_json_bytes(expected))
    output.write_bytes(conflicting_bytes)

    with pytest.raises(Phase4DemoReleaseError, match="conflicts with prior evidence"):
        _publish_final_receipt(output, expected)

    assert output.read_bytes() == conflicting_bytes
    assert not tuple(tmp_path.glob(".phase4-demo-release-receipt.json.incomplete-*"))
    conflict_files = tuple(tmp_path.glob(".phase4-demo-release-receipt.json.conflict-*"))
    assert len(conflict_files) == 1
    assert conflict_files[0].read_bytes() == canonical_json_bytes(expected)
