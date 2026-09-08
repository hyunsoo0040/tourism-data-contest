from __future__ import annotations

import os
from pathlib import Path

import pytest


def test_nvidia_journal_rejects_existing_root_through_symlinked_ancestor(
    tmp_path: Path,
) -> None:
    """Specified oracle: an existing journal never authorizes a symlinked path."""

    from itda.contracts.demo_profile_materialization import NVIDIA_AUTHORITY_SHA256
    from itda.pipeline.demo_profile_materialization import DurableNvidiaJournal

    authority = {"authority_sha256": NVIDIA_AUTHORITY_SHA256}
    real_parent = tmp_path / "real-parent"
    DurableNvidiaJournal(
        root=real_parent / "nvidia" / NVIDIA_AUTHORITY_SHA256,
        authority_receipt=authority,
    )
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink|directory"):
        DurableNvidiaJournal(
            root=linked_parent / "nvidia" / NVIDIA_AUTHORITY_SHA256,
            authority_receipt=authority,
        )


def test_nvidia_journal_missing_root_never_chmods_symlink_target(
    tmp_path: Path,
) -> None:
    """Specified oracle: rejection never changes metadata on an external target."""

    from itda.contracts.demo_profile_materialization import NVIDIA_AUTHORITY_SHA256
    from itda.pipeline.demo_profile_materialization import DurableNvidiaJournal

    journal_root = tmp_path / "root" / "nvidia" / NVIDIA_AUTHORITY_SHA256
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o755)
    outside.chmod(0o755)
    journal_root.parent.parent.mkdir(parents=True)
    journal_root.parent.symlink_to(outside, target_is_directory=True)

    with pytest.raises((OSError, ValueError), match="symlink|identity|uncertain|directory"):
        DurableNvidiaJournal(
            root=journal_root,
            authority_receipt={"authority_sha256": NVIDIA_AUTHORITY_SHA256},
        )
    assert outside.stat().st_mode & 0o777 == 0o755
    assert tuple(outside.iterdir()) == ()


def test_nvidia_journal_pins_parent_descriptor_during_ancestor_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Specified oracle: a pathname swap cannot redirect journal publication."""

    from itda.cli.freeze_preview import PublicationStateUncertainError
    from itda.contracts.demo_profile_materialization import NVIDIA_AUTHORITY_SHA256
    from itda.pipeline import demo_profile_materialization as materialization
    from itda.pipeline.demo_profile_materialization import DurableNvidiaJournal

    journal_parent = tmp_path / "root" / "nvidia"
    journal_parent.mkdir(parents=True)
    pinned_parent = tmp_path / "root" / "nvidia-pinned"
    outside = tmp_path / "outside"
    outside.mkdir()
    original_mkdir = materialization.os.mkdir

    def swap_after_staging(path, *args, **kwargs):
        result = original_mkdir(path, *args, **kwargs)
        if isinstance(path, str) and path.startswith(".phase5-nvidia-"):
            journal_parent.rename(pinned_parent)
            journal_parent.symlink_to(outside, target_is_directory=True)
        return result

    monkeypatch.setattr(materialization.os, "mkdir", swap_after_staging)

    with pytest.raises(PublicationStateUncertainError, match="parent identity"):
        DurableNvidiaJournal(
            root=journal_parent / NVIDIA_AUTHORITY_SHA256,
            authority_receipt={"authority_sha256": NVIDIA_AUTHORITY_SHA256},
        )

    assert tuple(outside.iterdir()) == ()
    assert (pinned_parent / NVIDIA_AUTHORITY_SHA256 / "authority.json").is_file()


def test_nvidia_journal_rejects_post_init_root_symlink_swap(tmp_path: Path) -> None:
    """Specified oracle: every journal read remains bound to the opened root."""

    from itda.contracts.demo_profile_materialization import NVIDIA_AUTHORITY_SHA256
    from itda.pipeline.demo_profile_materialization import DurableNvidiaJournal

    journal_root = tmp_path / "root" / NVIDIA_AUTHORITY_SHA256
    journal = DurableNvidiaJournal(
        root=journal_root,
        authority_receipt={"authority_sha256": NVIDIA_AUTHORITY_SHA256},
    )
    journal.record_live_start()
    moved_root = tmp_path / "moved-root"
    journal_root.rename(moved_root)
    journal_root.symlink_to(moved_root, target_is_directory=True)

    with pytest.raises((PermissionError, ValueError), match="symlink|identity|sealed|claimed"):
        journal.require_live_started()


def test_nvidia_journal_authority_read_survives_temporary_root_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Specified oracle: authority reads stay on the lifetime-pinned root fd."""

    from itda.contracts.demo_profile_materialization import NVIDIA_AUTHORITY_SHA256
    from itda.pipeline.demo_profile_materialization import DurableNvidiaJournal

    authority = {"authority_sha256": NVIDIA_AUTHORITY_SHA256}
    journal_root = tmp_path / "journal"
    journal = DurableNvidiaJournal(root=journal_root, authority_receipt=authority)
    journal.record_live_start()
    moved_root = tmp_path / "journal-pinned"
    foreign_root = tmp_path / "journal-foreign"
    foreign_root.mkdir()
    (foreign_root / "authority.json").write_bytes(b"{}")
    original_require = journal._require_root_identity
    swapped = False

    def swap_after_identity_check() -> None:
        nonlocal swapped
        original_require()
        if not swapped:
            journal_root.rename(moved_root)
            foreign_root.rename(journal_root)
            swapped = True

    monkeypatch.setattr(journal, "_require_root_identity", swap_after_identity_check)
    try:
        journal.require_live_started()
    finally:
        if swapped:
            journal_root.rename(foreign_root)
            moved_root.rename(journal_root)


def test_nvidia_live_start_never_replaces_existing_empty_claim_directory(
    tmp_path: Path,
) -> None:
    """Specified oracle: single-use publication is no-replace even for an empty directory."""

    from itda.contracts.demo_profile_materialization import NVIDIA_AUTHORITY_SHA256
    from itda.pipeline.demo_profile_materialization import DurableNvidiaJournal

    journal = DurableNvidiaJournal(
        root=tmp_path / "journal",
        authority_receipt={"authority_sha256": NVIDIA_AUTHORITY_SHA256},
    )
    claim = journal.root / "live-start"
    claim.mkdir()

    with pytest.raises(PermissionError, match="already been consumed"):
        journal.record_live_start()

    assert claim.is_dir()
    assert tuple(claim.iterdir()) == ()


def test_open_or_create_fsyncs_parent_when_concurrent_creator_wins(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Specified oracle: the FileExists loser still durably observes the child entry."""

    from itda.db import phase5_demo_release
    from itda.db.phase5_demo_release import _open_directory_chain, _open_or_create_directory

    root = tmp_path / "release-root"
    root.mkdir()
    root_descriptor = _open_directory_chain(root)
    original_mkdir = phase5_demo_release.os.mkdir
    original_fsync = phase5_demo_release.os.fsync
    synced_parent = False

    def concurrent_create(name: str, *args: object, **kwargs: object) -> None:
        original_mkdir(name, *args, **kwargs)
        raise FileExistsError(name)

    def track_fsync(descriptor: int) -> None:
        nonlocal synced_parent
        if descriptor == root_descriptor:
            synced_parent = True
        original_fsync(descriptor)

    monkeypatch.setattr(phase5_demo_release.os, "mkdir", concurrent_create)
    monkeypatch.setattr(phase5_demo_release.os, "fsync", track_fsync)
    child_descriptor = _open_or_create_directory(root_descriptor, "active")
    try:
        assert synced_parent is True
    finally:
        os.close(child_descriptor)
        os.close(root_descriptor)


def test_release_reader_rejects_symlinked_ancestor(tmp_path) -> None:
    from itda.db.phase5_demo_release import Phase5DemoReleaseError, _read_regular

    real_root = tmp_path / "real"
    real_root.mkdir()
    payload = real_root / "payload.json"
    payload.write_bytes(b"{}")
    linked_root = tmp_path / "linked"
    linked_root.symlink_to(real_root, target_is_directory=True)

    with pytest.raises(Phase5DemoReleaseError, match="RESTRICTED_PATH_SYMLINK"):
        _read_regular(linked_root / "payload.json", maximum_bytes=1024)


def test_failure_publisher_rejects_symlinked_ancestor(tmp_path) -> None:
    from itda.pipeline.demo_profile_materialization import (
        DemoProfileMaterializationFailure,
        publish_demo_profile_failure,
    )
    from itda.providers.zhipu_glm5v_profile import ZhipuGlm5vProfileAdapter

    adapter = ZhipuGlm5vProfileAdapter(secret="test-only-secret")
    result = adapter.consume_replay_chunks(
        place_id="canonical-dev-01",
        chunks=(b'{"error":{"code":"provider_rejected"}}',),
    )
    failure = DemoProfileMaterializationFailure(
        failed_place_id="canonical-dev-01",
        results=(result,),
        committed_cost_micro_usd=adapter.ledger.committed_micro_usd,
        outstanding_cost_micro_usd=adapter.ledger.outstanding_micro_usd,
    )
    real_root = tmp_path / "real"
    real_root.mkdir()
    linked_root = tmp_path / "linked"
    linked_root.symlink_to(real_root, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink"):
        publish_demo_profile_failure(failure, output_root=linked_root / "failures")
    assert list(real_root.iterdir()) == []


def test_private_failure_publisher_pins_parent_descriptor_during_ancestor_swap(
    tmp_path, monkeypatch
) -> None:
    from itda.pipeline import demo_profile_materialization as materialization
    from itda.pipeline.demo_profile_materialization import (
        DemoProfileMaterializationFailure,
        publish_demo_profile_failure,
    )
    from itda.providers.zhipu_glm5v_profile import ZhipuGlm5vProfileAdapter

    adapter = ZhipuGlm5vProfileAdapter(secret="test-only-secret")
    result = adapter.consume_replay_chunks(
        place_id="canonical-dev-01",
        chunks=(b'{"error":{"code":"provider_rejected"}}',),
    )
    failure = DemoProfileMaterializationFailure(
        failed_place_id="canonical-dev-01",
        results=(result,),
        committed_cost_micro_usd=adapter.ledger.committed_micro_usd,
        outstanding_cost_micro_usd=adapter.ledger.outstanding_micro_usd,
    )
    root = tmp_path / "root"
    output_root = root / "failures"
    output_root.mkdir(parents=True)
    pinned_root = root / "failures-pinned"
    outside = tmp_path / "outside"
    outside.mkdir()
    original_mkdir = materialization.os.mkdir

    def swap_after_staging(path, *args, **kwargs):
        result = original_mkdir(path, *args, **kwargs)
        if isinstance(path, str) and path.startswith(".phase5-profile-failure-"):
            output_root.rename(pinned_root)
            output_root.symlink_to(outside, target_is_directory=True)
        return result

    monkeypatch.setattr(materialization.os, "mkdir", swap_after_staging)
    from itda.cli.freeze_preview import PublicationStateUncertainError

    with pytest.raises(PublicationStateUncertainError, match="parent identity"):
        publish_demo_profile_failure(failure, output_root=output_root)

    assert len(list(pinned_root.iterdir())) == 1
    assert list(outside.iterdir()) == []


def test_activation_directory_descriptor_survives_ancestor_replacement(tmp_path) -> None:
    from itda.db.phase5_demo_release import (
        _create_private_temporary_at,
        _open_directory_chain,
        _open_or_create_directory,
        _read_regular_at,
    )

    root = tmp_path / "release"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    root_descriptor = _open_directory_chain(root)
    active_descriptor = _open_or_create_directory(root_descriptor, "active")
    try:
        active_path = root / "active"
        moved = root / "active-pinned"
        active_path.rename(moved)
        active_path.symlink_to(outside, target_is_directory=True)

        temporary = _create_private_temporary_at(active_descriptor, b"pinned")
        os.replace(
            temporary,
            "current.json",
            src_dir_fd=active_descriptor,
            dst_dir_fd=active_descriptor,
        )
        assert _read_regular_at(active_descriptor, "current.json", maximum_bytes=1024) == b"pinned"
        assert not (outside / "current.json").exists()
    finally:
        os.close(active_descriptor)
        os.close(root_descriptor)


def _recovery_smoke(candidate):
    from itda.contracts.demo_profile_materialization import (
        Phase5CandidateSmokeAttestation,
        seal_demo_contract,
    )

    fields = {
        "schema_version": "itda.phase5-candidate-smoke-attestation.v1",
        "state": "COMPLETE",
        "candidate_sha256": candidate.release_sha256,
        "release_sha256": candidate.release_sha256,
        "generation_sha256": candidate.generation_sha256,
        "generation_receipt_sha256": candidate.generation_receipt_sha256,
        "membership_sha256": candidate.membership_sha256,
        "source_inventory_sha256": candidate.source_inventory_sha256,
        "checkout_sha256": candidate.checkout_sha256,
        "config_sha256": candidate.config_sha256,
        "kernel_sha256": candidate.kernel_sha256,
        "policy_sha256": candidate.policy_sha256,
        "hard_duplicate_adjudication_sha256": candidate.hard_duplicate_adjudication_sha256,
        "cannot_coappear_authority_sha256": candidate.cannot_coappear_authority_sha256,
        "activation_source_file_sha256": candidate.activation_source_file_sha256,
        "activation_dataset_sha256": candidate.activation_dataset_sha256,
        "activation_suite_sha256": candidate.activation_suite_sha256,
        "scenario_results": {
            key: value.model_dump(mode="json") for key, value in candidate.scenario_results.items()
        },
        "contrast_suite_sha256": candidate.contrast_suite_sha256,
        "contrast_results": [value.model_dump(mode="json") for value in candidate.contrast_results],
        "backend_digest": "1" * 64,
        "storage_digest": "2" * 64,
        "evidence_digest": "3" * 64,
        "ordinary_unavailable_digest": "4" * 64,
        "browser_digest": "5" * 64,
    }
    return Phase5CandidateSmokeAttestation.model_validate(
        seal_demo_contract(fields, digest_field="smoke_attestation_sha256")
    )


def _recovery_attestation(candidate, smoke):
    from itda.contracts.demo_profile_materialization import (
        Phase5ActivationAttestation,
        seal_demo_contract,
    )

    fields = {
        "schema_version": "itda.phase5-activation-attestation.v1",
        "state": "COMPLETE_POSITIVE",
        "candidate_sha256": candidate.release_sha256,
        "smoke_attestation_sha256": smoke.smoke_attestation_sha256,
        "activation_intent_sha256": "6" * 64,
        "promotion_sha256": "7" * 64,
        "policy_sha256": candidate.policy_sha256,
        "hard_duplicate_adjudication_sha256": candidate.hard_duplicate_adjudication_sha256,
        "cannot_coappear_authority_sha256": candidate.cannot_coappear_authority_sha256,
        "activation_suite_sha256": candidate.activation_suite_sha256,
        "scenario_results": {
            key: value.model_dump(mode="json") for key, value in candidate.scenario_results.items()
        },
        "contrast_suite_sha256": candidate.contrast_suite_sha256,
        "contrast_results": [value.model_dump(mode="json") for value in candidate.contrast_results],
        "ordinary_run_results": {
            key: f"{index + 11:064x}" for index, key in enumerate(candidate.scenario_results)
        },
    }
    return Phase5ActivationAttestation.model_validate(
        seal_demo_contract(fields, digest_field="attestation_sha256")
    )


def test_candidate_smoke_and_prepared_intent_require_exact_maps_before_promotion(
    tmp_path: Path,
) -> None:
    from itda.db.phase5_demo_release import Phase5DemoReleaseError, Phase5DemoReleaseStore
    from tests.integration.test_demo_scored_release import _nvidia_live_generation
    from tests.security.test_phase5_release_authority import _recovery_maps

    root = tmp_path / "smoke-intent"
    generation, expected = _nvidia_live_generation(root)
    store = Phase5DemoReleaseStore(root=root, expected_place_ids=expected)
    scenario_results, contrast_results = _recovery_maps(expected)
    candidate = store.build_recovery_candidate(
        generation.name,
        scenario_results=scenario_results,
        contrast_results=contrast_results,
    )
    smoke = _recovery_smoke(candidate)
    assert store.validate_candidate_smoke(candidate.release_sha256, smoke) == smoke
    intent = store.prepare_activation_intent(
        candidate.release_sha256,
        smoke,
        expected_current_sha256=None,
    )
    assert intent.state == "PREPARED"
    assert store.read_recovery_lifecycle().state == "PREPARED"
    with pytest.raises(Phase5DemoReleaseError, match="SMOKE"):
        store.promote(
            candidate.release_sha256,
            smoke_attestation_sha256="f" * 64,
            activation_intent=intent,
            expected_current_sha256=None,
        )
    assert not (root / "recovery-active.json").exists()


def test_post_promotion_failure_invalidates_before_rollback_even_if_rollback_fails(
    tmp_path: Path,
) -> None:
    from itda.db.phase5_demo_release import Phase5DemoReleaseError, Phase5DemoReleaseStore
    from tests.integration.test_demo_scored_release import _nvidia_live_generation
    from tests.security.test_phase5_release_authority import _recovery_maps

    events: list[str] = []

    def inject(stage: str) -> None:
        events.append(stage)
        if stage == "after_pointer":
            raise OSError("fault after pointer")
        if stage == "before_rollback":
            raise OSError("rollback unavailable")

    root = tmp_path / "invalidate-first"
    generation, expected = _nvidia_live_generation(root)
    store = Phase5DemoReleaseStore(
        root=root,
        expected_place_ids=expected,
        fault_injector=inject,
    )
    scenario_results, contrast_results = _recovery_maps(expected)
    candidate = store.build_recovery_candidate(
        generation.name,
        scenario_results=scenario_results,
        contrast_results=contrast_results,
    )
    smoke = _recovery_smoke(candidate)
    store.validate_candidate_smoke(candidate.release_sha256, smoke)
    intent = store.prepare_activation_intent(
        candidate.release_sha256, smoke, expected_current_sha256=None
    )
    attestation = _recovery_attestation(candidate, smoke)

    with pytest.raises(Phase5DemoReleaseError, match="POST_PROMOTION"):
        store.promote(
            candidate.release_sha256,
            smoke_attestation_sha256=smoke,
            activation_intent=intent,
            expected_current_sha256=None,
            activation_attestation=attestation,
        )

    lifecycle = store.read_recovery_lifecycle()
    assert lifecycle.state in {"INVALIDATED", "QUARANTINED"}
    assert store.resolve_active() is None
    assert events.index("after_invalidation") < events.index("before_rollback")
    assert (root / "rollbacks").is_dir()
    rollback_files = tuple((root / "rollbacks").iterdir())
    assert rollback_files
    assert "ROLLBACK_FAILED" in rollback_files[0].read_text(encoding="utf-8")
