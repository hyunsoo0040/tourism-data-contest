"""Security contracts for the inactive catalog-v2 revision and approval request."""

from __future__ import annotations

import importlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType

import pytest

from itda.domain.canonical import canonical_json_bytes, canonical_sha256

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
BUNDLE_ROOT = "3b72d3141e61925370b089169401a1ea23cf818e283100cdef51299a8ddb9f06"
BUNDLE_PATH = (
    REPOSITORY_ROOT
    / "artifacts/restricted/catalog/v2/review/adjudication-bundles"
    / BUNDLE_ROOT
    / "catalog-adjudication-bundle.json"
)


def _capability() -> ModuleType:
    return importlib.import_module("itda.contracts.catalog_release")


def _revision(capability: ModuleType) -> object:
    return capability.build_catalog_v2_revision(
        BUNDLE_PATH,
        repository_root=REPOSITORY_ROOT,
    )


def _canonical_file(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(payload))


def test_builds_and_verifies_exact_inactive_revision(tmp_path: Path) -> None:
    capability = _capability()
    first = _revision(capability)
    second = _revision(capability)
    assert canonical_json_bytes(first.model_dump(mode="json")) == canonical_json_bytes(
        second.model_dump(mode="json")
    )
    assert first.status == "SELECTED_UNAPPROVED"
    assert first.active_revision_sha256 is None
    assert len(first.ordered_place_ids) == 36
    assert len(set(first.ordered_place_ids)) == 36
    assert first.adjudication_bundle_root_sha256 == BUNDLE_ROOT
    assert first.representation_attestation.feasibility_result == "FEASIBLE"
    assert first.representation_attestation.raw_eligible_group_counts == {
        "history_culture": 13,
        "history_scenery_boundary": 6,
        "image_modern_content": 8,
        "rest_walk_immersion": 13,
    }
    assert first.representation_attestation.exact_quotas == {
        "history_culture": 12,
        "history_scenery_boundary": 6,
        "image_modern_content": 7,
        "rest_walk_immersion": 11,
    }
    assert first.representation_attestation.fixed_group_tie_order == (
        "history_culture",
        "history_scenery_boundary",
        "image_modern_content",
        "rest_walk_immersion",
    )
    assert (
        first.representation_attestation.source_neutral_comparator
        == "canonical-utf8-source-neutral-id-v1"
    )

    destination = tmp_path / "catalog-revision.json"
    capability.publish_catalog_v2_revision(first, destination)
    verified = capability.verify_catalog_v2_revision(
        destination,
        repository_root=REPOSITORY_ROOT,
        require_inactive=True,
    )
    assert verified.catalog_revision_sha256 == first.catalog_revision_sha256
    original = destination.read_bytes()
    with pytest.raises(FileExistsError):
        capability.publish_catalog_v2_revision(first, destination)
    assert destination.read_bytes() == original


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("representation_policy_version", "stale-policy"),
        ("representation_rule_table_sha256", "0" * 64),
        ("eligible_pool_sha256", "0" * 64),
        (
            "raw_eligible_group_counts",
            {
                "history_culture": 12,
                "history_scenery_boundary": 7,
                "image_modern_content": 8,
                "rest_walk_immersion": 13,
            },
        ),
        (
            "exact_quotas",
            {
                "history_culture": 11,
                "history_scenery_boundary": 7,
                "image_modern_content": 7,
                "rest_walk_immersion": 11,
            },
        ),
        ("feasibility_result", "REPRESENTATION_INFEASIBLE"),
        ("source_neutral_comparator", "caller-order-v1"),
        (
            "fixed_group_tie_order",
            [
                "rest_walk_immersion",
                "image_modern_content",
                "history_scenery_boundary",
                "history_culture",
            ],
        ),
    ],
)
def test_revision_rejects_rehashed_representation_drift(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    capability = _capability()
    payload = _revision(capability).model_dump(mode="json")
    payload["representation_attestation"][field] = value
    payload["representation_attestation"]["representation_attestation_sha256"] = canonical_sha256(
        {
            key: item
            for key, item in payload["representation_attestation"].items()
            if key != "representation_attestation_sha256"
        }
    )
    payload["catalog_revision_sha256"] = canonical_sha256(
        {key: item for key, item in payload.items() if key != "catalog_revision_sha256"}
    )
    path = tmp_path / f"tampered-{field}.json"
    _canonical_file(path, payload)
    with pytest.raises(ValueError, match="representation|quota|policy|comparator|tie|parent"):
        capability.verify_catalog_v2_revision(
            path,
            repository_root=REPOSITORY_ROOT,
            require_inactive=True,
        )


def test_revision_rejects_stale_code_parent_and_arbitrary_json(tmp_path: Path) -> None:
    capability = _capability()
    payload = _revision(capability).model_dump(mode="json")
    code_path = next(iter(payload["code_version_hashes"]))
    payload["code_version_hashes"][code_path] = "0" * 64
    payload["catalog_revision_sha256"] = canonical_sha256(
        {key: item for key, item in payload.items() if key != "catalog_revision_sha256"}
    )
    stale = tmp_path / "stale.json"
    _canonical_file(stale, payload)
    with pytest.raises(ValueError, match="code.*stale|version hash"):
        capability.verify_catalog_v2_revision(
            stale,
            repository_root=REPOSITORY_ROOT,
            require_inactive=True,
        )

    arbitrary = tmp_path / "arbitrary.json"
    _canonical_file(arbitrary, {"catalog_revision_sha256": "1" * 64})
    with pytest.raises(ValueError, match="revision|canonical|field"):
        capability.verify_catalog_v2_revision(
            arbitrary,
            repository_root=REPOSITORY_ROOT,
            require_inactive=True,
        )


def test_approval_request_binds_exact_inactive_revision(tmp_path: Path) -> None:
    capability = _capability()
    revision_path = tmp_path / "catalog-revision.json"
    capability.publish_catalog_v2_revision(_revision(capability), revision_path)
    issued_at = datetime.now(UTC).replace(microsecond=0)
    state, request = capability.build_catalog_v2_approval_request(
        revision_path,
        repository_root=REPOSITORY_ROOT,
        reviewer_id="phase2-operator",
        nonce="a" * 64,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(days=7),
    )
    assert state.status == "SELECTED_UNAPPROVED"
    assert state.active_revision_sha256 is None
    assert state.catalog_approval_sha256 is None
    assert request.action == "catalog-approve"
    assert request.state_attestation_sha256 == state.state_attestation_sha256
    assert request.catalog_revision_sha256 == state.catalog_revision_sha256
    assert request.target_sha256 == state.approval_target_sha256
    assert request.representation_attestation_sha256 == (
        state.representation_attestation.representation_attestation_sha256
    )

    state_path = tmp_path / "catalog-approval-state-attestation.json"
    request_path = tmp_path / "catalog-approval-request.json"
    capability.publish_catalog_v2_approval_request(
        state,
        request,
        state_path=state_path,
        request_path=request_path,
    )
    checked = capability.check_catalog_v2_approval_request(
        request_path,
        state_path,
        revision_path=revision_path,
        repository_root=REPOSITORY_ROOT,
    )
    assert checked.request_sha256 == request.request_sha256
    assert state_path.stat().st_mode & 0o777 == 0o600
    assert request_path.stat().st_mode & 0o777 == 0o600
    assert revision_path.read_bytes() == canonical_json_bytes(
        _revision(capability).model_dump(mode="json")
    )
    assert not (tmp_path / "catalog-approval.json").exists()


def test_approval_consumes_exact_authority_once_without_activation(tmp_path: Path) -> None:
    capability = _capability()
    revision_path = tmp_path / "catalog-revision.json"
    state_path = tmp_path / "catalog-approval-state-attestation.json"
    request_path = tmp_path / "catalog-approval-request.json"
    approval_path = tmp_path / "catalog-approval.json"
    capability.publish_catalog_v2_revision(_revision(capability), revision_path)
    issued_at = datetime.now(UTC).replace(microsecond=0)
    state, request = capability.build_catalog_v2_approval_request(
        revision_path,
        repository_root=REPOSITORY_ROOT,
        reviewer_id="phase2-operator",
        nonce="b" * 64,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(days=7),
    )
    capability.publish_catalog_v2_approval_request(
        state,
        request,
        state_path=state_path,
        request_path=request_path,
    )
    context = capability.catalog_v2_approval_issuance_context(
        request_path,
        state_path,
        revision_path=revision_path,
        repository_root=REPOSITORY_ROOT,
    )
    descriptor_path = tmp_path / "authority.json"
    _canonical_file(
        descriptor_path,
        {
            "schema_version": "itda.catalog-approval-authority-descriptor.v2",
            "issuance_context": context.model_dump(mode="json"),
            "authority_token": context.expected_token().serialize(),
        },
    )
    os.chmod(descriptor_path, 0o600)
    approval = capability.approve_catalog_v2(
        authority_descriptor_path=descriptor_path,
        request_path=request_path,
        state_path=state_path,
        revision_path=revision_path,
        approval_path=approval_path,
        nonce_ledger_root=tmp_path / ".authority-ledger",
        repository_root=REPOSITORY_ROOT,
        approved_at=issued_at + timedelta(seconds=1),
    )
    assert approval.status == "APPROVED_INACTIVE"
    assert approval.active_revision_sha256 is None
    assert approval.activation_event_sha256 is None
    assert (
        capability.verify_catalog_v2_approval(
            approval_path,
            repository_root=REPOSITORY_ROOT,
            require_inactive=True,
        ).catalog_approval_sha256
        == approval.catalog_approval_sha256
    )
    with pytest.raises(RuntimeError, match="nonce already consumed"):
        capability.approve_catalog_v2(
            authority_descriptor_path=descriptor_path,
            request_path=request_path,
            state_path=state_path,
            revision_path=revision_path,
            approval_path=approval_path,
            nonce_ledger_root=tmp_path / ".authority-ledger",
            repository_root=REPOSITORY_ROOT,
            approved_at=issued_at + timedelta(seconds=2),
        )


def test_request_pair_rolls_back_first_link_when_second_publish_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability = _capability()
    revision_path = tmp_path / "catalog-revision.json"
    capability.publish_catalog_v2_revision(_revision(capability), revision_path)
    issued_at = datetime.now(UTC).replace(microsecond=0)
    state, request = capability.build_catalog_v2_approval_request(
        revision_path,
        repository_root=REPOSITORY_ROOT,
        reviewer_id="phase2-operator",
        nonce="c" * 64,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(days=7),
    )
    state_path = tmp_path / "state.json"
    request_path = tmp_path / "request.json"
    real_link = os.link
    calls = 0

    def fail_second_link(source: object, destination: object, **kwargs: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated partial publish")
        real_link(source, destination, **kwargs)

    monkeypatch.setattr(os, "link", fail_second_link)
    with pytest.raises(OSError, match="partial publish"):
        capability.publish_catalog_v2_approval_request(
            state,
            request,
            state_path=state_path,
            request_path=request_path,
        )
    assert not state_path.exists()
    assert not request_path.exists()


def test_cli_declares_plan21_and_plan22_verification_modes() -> None:
    cli = importlib.import_module("itda.cli.approve_catalog")
    help_text = cli.build_parser().format_help()
    for flag in (
        "--materialize-v2-revision",
        "--verify-v2-revision",
        "--issue-v2-approval-request",
        "--check-v2-approval-request",
        "--approve-v2",
        "--verify-v2-approval",
        "--require-inactive",
    ):
        assert flag in help_text


def test_restricted_outputs_never_create_activation_or_split_artifacts(tmp_path: Path) -> None:
    capability = _capability()
    revision = _revision(capability)
    revision_path = tmp_path / "catalog-revision.json"
    capability.publish_catalog_v2_revision(revision, revision_path)
    assert revision.active_revision_sha256 is None
    assert not any("activation" in path.name for path in tmp_path.rglob("*"))
    assert not any("split" in path.name for path in tmp_path.rglob("*"))
    serialized = json.dumps(revision.model_dump(mode="json"), sort_keys=True)
    assert "dev_members" not in serialized
    assert "blind_members" not in serialized
