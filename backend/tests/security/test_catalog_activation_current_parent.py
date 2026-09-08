"""Security contracts for the catalog activation current-parent successor."""

from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path

import pytest

from itda.domain.canonical import canonical_json_bytes

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
EVENT_PATH = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/activation/catalog-activation-event.json"
)
BEFORE_GUARD = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/release/gap-closure-guards/"
    "02-61-protected-before.json"
)
HISTORICAL_PROOF_COMMIT = "788d79a"
ATTESTATION_PATH = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/activation/"
    "catalog-activation-current-parent-attestation-v1.json"
)
LEDGER_PATH = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/activation/.authority-ledger/"
    "authority-consumption-ledger.jsonl"
)


def _capability():
    from itda.contracts import catalog_activation_current_parent

    return catalog_activation_current_parent


def _git_bytes(revision: str, relpath: str) -> bytes:
    return subprocess.run(
        ["git", "show", f"{revision}:{relpath}"],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
    ).stdout


def _historical_and_current(capability) -> tuple[dict[str, bytes], dict[str, bytes]]:
    historical = {
        path: _git_bytes(HISTORICAL_PROOF_COMMIT, path) for path in capability.ROLLBACK_PROOF_PATHS
    }
    current = {
        path: (REPOSITORY_ROOT / path).read_bytes() for path in capability.ROLLBACK_PROOF_PATHS
    }
    return historical, current


def test_diagnostic_reconstructs_exact_historical_and_current_parents() -> None:
    capability = _capability()

    diagnosis = capability.diagnose_current_parent(
        REPOSITORY_ROOT,
        EVENT_PATH,
        historical_proof_commit=HISTORICAL_PROOF_COMMIT,
    )

    assert diagnosis.historical_rollback_capability_sha256 == (
        "fb079326068d4e0bf88d87e0d563abd770add992f878235bc948284e4744c6b3"
    )
    assert diagnosis.current_rollback_capability_sha256 == (
        "b75a9c3329c5db11d27db0923706d970f2ef370a75d563cb4ae27f91f602890b"
    )
    assert diagnosis.changed_proof_paths == ("backend/src/itda/contracts/authority.py",)
    assert diagnosis.added_authority_actions == (
        "sqlite-manifest-initialize",
        "sqlite-real-manifest-seal",
    )
    assert diagnosis.owner_commits == {
        "sqlite-manifest-initialize": "74b8a3e",
        "sqlite-real-manifest-seal": "4279cfb",
    }
    assert diagnosis.event_sha256 == (
        "db6b24df96c8d804b697bee7e8495ecd6a1afb729cc0cf127d53522f7b25d39b"
    )


def test_diagnostic_proof_migration_rejects_second_path_or_extra_authority_hunk() -> None:
    capability = _capability()
    historical, current = _historical_and_current(capability)

    second_path = dict(current)
    second_path["backend/src/itda/cli/activate_catalog.py"] += b"\n# drift\n"
    with pytest.raises(capability.CatalogActivationCurrentParentError, match="proof path"):
        capability.validate_proof_file_migration(historical, second_path)

    extra_hunk = dict(current)
    extra_hunk["backend/src/itda/contracts/authority.py"] += b"\n# drift\n"
    with pytest.raises(capability.CatalogActivationCurrentParentError, match="authority"):
        capability.validate_proof_file_migration(historical, extra_hunk)


def test_diagnostic_proof_migration_rejects_removed_or_reordered_catalog_action() -> None:
    capability = _capability()
    historical, current = _historical_and_current(capability)
    authority_path = "backend/src/itda/contracts/authority.py"

    removed = dict(current)
    removed[authority_path] = removed[authority_path].replace(b'    "catalog-rollback",\n', b"", 1)
    with pytest.raises(capability.CatalogActivationCurrentParentError, match="authority"):
        capability.validate_proof_file_migration(historical, removed)

    reordered = dict(current)
    reordered[authority_path] = reordered[authority_path].replace(
        b'    "catalog-activate",\n    "catalog-rollback",\n',
        b'    "catalog-rollback",\n    "catalog-activate",\n',
        1,
    )
    with pytest.raises(capability.CatalogActivationCurrentParentError, match="authority"):
        capability.validate_proof_file_migration(historical, reordered)


def test_diagnostic_rejects_dirty_proof_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability = _capability()
    original = capability._stable_worktree_proof_files

    def dirty(root: Path) -> dict[str, bytes]:
        payloads = original(root)
        payloads["backend/src/itda/contracts/authority.py"] += b"\n# dirty\n"
        return payloads

    monkeypatch.setattr(capability, "_stable_worktree_proof_files", dirty)
    with pytest.raises(capability.CatalogActivationCurrentParentError, match="stage-0|dirty"):
        capability.diagnose_current_parent(
            REPOSITORY_ROOT,
            EVENT_PATH,
            historical_proof_commit=HISTORICAL_PROOF_COMMIT,
        )


def test_diagnostic_rejects_wrong_owner_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability = _capability()
    monkeypatch.setattr(
        capability,
        "AUTHORITY_ACTION_OWNER_COMMITS",
        {
            "sqlite-manifest-initialize": "788d79a",
            "sqlite-real-manifest-seal": "4279cfb",
        },
    )
    with pytest.raises(capability.CatalogActivationCurrentParentError, match="owner commit"):
        capability.diagnose_current_parent(
            REPOSITORY_ROOT,
            EVENT_PATH,
            historical_proof_commit=HISTORICAL_PROOF_COMMIT,
        )


def test_diagnostic_rejects_historical_fingerprint_or_event_mutation(tmp_path: Path) -> None:
    capability = _capability()
    event = json.loads(EVENT_PATH.read_bytes())

    wrong_parent = copy.deepcopy(event)
    wrong_parent["rollback_capability_sha256"] = "0" * 64
    wrong_parent["event_sha256"] = None
    wrong_parent_path = tmp_path / "wrong-parent.json"
    from itda.contracts.catalog_activation import CatalogActivationEventV2

    wrong_parent_model = CatalogActivationEventV2.model_validate(wrong_parent)
    wrong_parent_path.write_bytes(canonical_json_bytes(wrong_parent_model.model_dump(mode="json")))
    with pytest.raises(capability.CatalogActivationCurrentParentError, match="historical"):
        capability.diagnose_current_parent(
            REPOSITORY_ROOT,
            wrong_parent_path,
            historical_proof_commit=HISTORICAL_PROOF_COMMIT,
        )

    mutated = copy.deepcopy(event)
    mutated["reviewer_id"] = "attacker"
    mutated_path = tmp_path / "mutated-event.json"
    mutated_path.write_bytes(canonical_json_bytes(mutated))
    with pytest.raises(capability.CatalogActivationCurrentParentError, match="event"):
        capability.diagnose_current_parent(
            REPOSITORY_ROOT,
            mutated_path,
            historical_proof_commit=HISTORICAL_PROOF_COMMIT,
        )


def test_protected_manifest_is_private_untracked_and_membership_free() -> None:
    capability = _capability()
    manifest = capability.verify_protected_manifest_file(
        REPOSITORY_ROOT,
        BEFORE_GUARD,
        plan_id="02-61",
        stage="before",
    )

    assert BEFORE_GUARD.stat().st_mode & 0o777 == 0o600
    assert manifest["plan_id"] == "02-61"
    assert manifest["stage"] == "before"
    assert manifest["owner_count"] > 100
    assert (
        subprocess.run(
            ["git", "check-ignore", "-q", str(BEFORE_GUARD)],
            cwd=REPOSITORY_ROOT,
            check=False,
        ).returncode
        == 0
    )
    assert (
        subprocess.run(
            ["git", "ls-files", "--error-unmatch", str(BEFORE_GUARD)],
            cwd=REPOSITORY_ROOT,
            check=False,
            capture_output=True,
        ).returncode
        != 0
    )
    rendered = json.dumps(manifest, ensure_ascii=False, sort_keys=True).lower()
    for forbidden in capability.PROTECTED_FORBIDDEN_TERMS:
        assert forbidden not in rendered


def test_protected_manifest_rejects_tracked_permission_or_membership_substitution(
    tmp_path: Path,
) -> None:
    capability = _capability()
    payload = json.loads(BEFORE_GUARD.read_bytes())

    permission_bearing = dict(payload)
    permission_bearing["authority_token"] = "secret"
    with pytest.raises(capability.CatalogActivationCurrentParentError, match="schema|forbidden"):
        capability.validate_protected_manifest_payload(
            REPOSITORY_ROOT,
            permission_bearing,
            plan_id="02-61",
            stage="before",
        )

    leaking = copy.deepcopy(payload)
    leaking["owners"][0]["member_ids"] = ["forbidden"]
    with pytest.raises(capability.CatalogActivationCurrentParentError, match="schema|forbidden"):
        capability.validate_protected_manifest_payload(
            REPOSITORY_ROOT,
            leaking,
            plan_id="02-61",
            stage="before",
        )


def test_current_parent_cli_exposes_only_read_only_task1_modes() -> None:
    from itda.cli.verify_catalog_activation_current_parent import build_parser

    parser = build_parser()
    parsed = parser.parse_args(
        [
            "--diagnose-current-parent",
            str(EVENT_PATH),
            "--historical-proof-commit",
            HISTORICAL_PROOF_COMMIT,
        ]
    )
    assert parsed.diagnose_current_parent == EVENT_PATH
    help_text = parser.format_help()
    assert "--capture-protected-manifest" in help_text
    assert "--verify-protected-manifest" in help_text
    assert "--activate" not in help_text
    assert "--rollback" not in help_text


def _passing_hostile_result(capability):
    return capability.HostileTestResult(
        command=(
            "python",
            "-m",
            "pytest",
            "tests/security/test_catalog_activation.py",
            "-q",
        ),
        test_file_sha256=capability.hash_file(
            REPOSITORY_ROOT / "backend/tests/security/test_catalog_activation.py"
        ),
        exit_code=0,
        status="PASS",
    )


def test_attestation_payload_is_deterministic_and_binds_live_current_head() -> None:
    capability = _capability()
    first = capability.build_current_parent_attestation_payload(
        REPOSITORY_ROOT,
        EVENT_PATH,
        BEFORE_GUARD,
        historical_proof_commit=HISTORICAL_PROOF_COMMIT,
        hostile_test_result=_passing_hostile_result(capability),
    )
    second = capability.build_current_parent_attestation_payload(
        REPOSITORY_ROOT,
        EVENT_PATH,
        BEFORE_GUARD,
        historical_proof_commit=HISTORICAL_PROOF_COMMIT,
        hostile_test_result=_passing_hostile_result(capability),
    )

    assert canonical_json_bytes(first.model_dump(mode="json")) == canonical_json_bytes(
        second.model_dump(mode="json")
    )
    assert first.event_sha256 == first.current_event_sha256
    assert first.event_sequence == 1
    assert first.catalog_revision_sha256 == first.active_revision_sha256
    assert first.historical_rollback_capability_sha256.startswith("fb079326")
    assert first.current_rollback_capability_sha256.startswith("b75a9c33")
    assert first.protected_set_sha256
    assert first.attestation_sha256


def test_successor_verifier_preserves_strict_historical_rejection() -> None:
    capability = _capability()
    from itda.contracts.catalog_activation import verify_catalog_activation_event

    with pytest.raises(ValueError, match="current verified parents"):
        verify_catalog_activation_event(
            EVENT_PATH,
            events_root=EVENT_PATH.parent,
            approval_path=(
                REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/approval/catalog-approval.json"
            ),
            repository_root=REPOSITORY_ROOT,
            require_current=True,
        )

    attestation = capability.build_current_parent_attestation_payload(
        REPOSITORY_ROOT,
        EVENT_PATH,
        BEFORE_GUARD,
        historical_proof_commit=HISTORICAL_PROOF_COMMIT,
        hostile_test_result=_passing_hostile_result(capability),
    )
    verified = capability.validate_current_parent_attestation_payload(
        REPOSITORY_ROOT,
        attestation.model_dump(mode="json"),
        EVENT_PATH,
        require_current=True,
        hostile_test_result=_passing_hostile_result(capability),
    )
    assert verified.attestation_sha256 == attestation.attestation_sha256


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("current_rollback_capability_sha256", "0" * 64),
        ("current_event_sha256", "1" * 64),
        ("event_file_sha256", "2" * 64),
        ("migration_sha256", "3" * 64),
    ],
)
def test_attestation_rejects_stale_fingerprint_head_or_proof_hash(
    field: str,
    replacement: str,
) -> None:
    capability = _capability()
    attestation = capability.build_current_parent_attestation_payload(
        REPOSITORY_ROOT,
        EVENT_PATH,
        BEFORE_GUARD,
        historical_proof_commit=HISTORICAL_PROOF_COMMIT,
        hostile_test_result=_passing_hostile_result(capability),
    ).model_dump(mode="json")
    attestation[field] = replacement
    attestation["attestation_sha256"] = None

    with pytest.raises(capability.CatalogActivationCurrentParentError):
        capability.validate_current_parent_attestation_payload(
            REPOSITORY_ROOT,
            attestation,
            EVENT_PATH,
            require_current=True,
            hostile_test_result=_passing_hostile_result(capability),
        )


def test_attestation_rejects_owner_commit_drift() -> None:
    capability = _capability()
    attestation = capability.build_current_parent_attestation_payload(
        REPOSITORY_ROOT,
        EVENT_PATH,
        BEFORE_GUARD,
        historical_proof_commit=HISTORICAL_PROOF_COMMIT,
        hostile_test_result=_passing_hostile_result(capability),
    ).model_dump(mode="json")
    attestation["owner_commits"]["sqlite-manifest-initialize"] = "788d79a"
    attestation["attestation_sha256"] = None

    with pytest.raises(capability.CatalogActivationCurrentParentError, match="attestation"):
        capability.validate_current_parent_attestation_payload(
            REPOSITORY_ROOT,
            attestation,
            EVENT_PATH,
            require_current=True,
            hostile_test_result=_passing_hostile_result(capability),
        )


def test_attestation_build_detects_event_or_ledger_identity_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability = _capability()
    original = capability.snapshot_authority_state
    calls = 0

    def changing(root: Path, event_path: Path):
        nonlocal calls
        calls += 1
        snapshot = original(root, event_path)
        if calls == 2:
            payload = snapshot.model_dump(mode="json")
            payload["ledger_identity"]["mtime_ns"] += 1
            payload["snapshot_sha256"] = None
            return capability.AuthorityStateSnapshot.model_validate(payload)
        return snapshot

    monkeypatch.setattr(capability, "snapshot_authority_state", changing)
    with pytest.raises(capability.CatalogActivationCurrentParentError, match="event|ledger"):
        capability.build_current_parent_attestation(
            REPOSITORY_ROOT,
            ATTESTATION_PATH,
            EVENT_PATH,
            BEFORE_GUARD,
            historical_proof_commit=HISTORICAL_PROOF_COMMIT,
            hostile_test_runner=lambda _: _passing_hostile_result(capability),
        )


def test_attestation_publication_is_no_replace_exact_existing_and_private(
    tmp_path: Path,
) -> None:
    capability = _capability()
    payload = canonical_json_bytes({"safe": True})
    target = tmp_path / "attestation.json"

    assert capability.publish_attestation_no_replace(target, payload) == "PUBLISHED"
    first = target.stat()
    assert capability.publish_attestation_no_replace(target, payload) == (
        "ALREADY_PRESENT_VERIFIED"
    )
    second = target.stat()
    assert (first.st_dev, first.st_ino, first.st_mtime_ns) == (
        second.st_dev,
        second.st_ino,
        second.st_mtime_ns,
    )
    assert first.st_mode & 0o777 == 0o600
    assert first.st_nlink == 1

    target.chmod(0o640)
    with pytest.raises(capability.CatalogActivationCurrentParentError, match="mode|link"):
        capability.publish_attestation_no_replace(target, payload)


def test_attestation_publication_rejects_collision_symlink_and_hardlink(
    tmp_path: Path,
) -> None:
    capability = _capability()
    payload = canonical_json_bytes({"safe": True})

    collision = tmp_path / "collision.json"
    collision.write_bytes(canonical_json_bytes({"safe": False}))
    collision.chmod(0o600)
    with pytest.raises(capability.CatalogActivationCurrentParentError, match="differs"):
        capability.publish_attestation_no_replace(collision, payload)

    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(collision)
    with pytest.raises(capability.CatalogActivationCurrentParentError):
        capability.publish_attestation_no_replace(symlink, payload)

    hardlink = tmp_path / "hardlink.json"
    hardlink.hardlink_to(collision)
    with pytest.raises(capability.CatalogActivationCurrentParentError, match="mode|link"):
        capability.publish_attestation_no_replace(hardlink, collision.read_bytes())


def test_current_parent_cli_exposes_attestation_without_mutation_flags() -> None:
    from itda.cli.verify_catalog_activation_current_parent import build_parser

    parser = build_parser()
    build = parser.parse_args(
        [
            "--build-current-parent-attestation",
            str(ATTESTATION_PATH),
            "--event",
            str(EVENT_PATH),
            "--protected-before",
            str(BEFORE_GUARD),
        ]
    )
    verify = parser.parse_args(
        [
            "--verify-current-parent-attestation",
            str(ATTESTATION_PATH),
            "--event",
            str(EVENT_PATH),
            "--require-current",
        ]
    )
    assert build.build_current_parent_attestation == ATTESTATION_PATH
    assert verify.verify_current_parent_attestation == ATTESTATION_PATH
    help_text = parser.format_help()
    assert "--activate" not in help_text
    assert "--rollback" not in help_text
