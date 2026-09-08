"""Hostile lifecycle tests for catalog-v2 activation and append-only rollback."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from itda.contracts.authority import AuthorityMutationUncertain, AuthorityReplayError
from itda.domain.canonical import canonical_json_bytes

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
APPROVAL_PATH = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/approval/catalog-approval.json"
)
REVISION_PATH = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/revisions/catalog-revision.json"
)
NOW = datetime(2026, 8, 1, 14, 0, tzinfo=UTC)


def _capability():
    from itda.contracts import catalog_activation

    return catalog_activation


def _write(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(payload))
    path.chmod(0o600)


def _bundle(
    capability,
    tmp_path: Path,
    *,
    action: str = "catalog-activate",
    nonce: str = "a" * 64,
    issued_at: datetime = NOW,
):
    events_root = tmp_path / "events"
    state, request = capability.build_catalog_activation_request(
        APPROVAL_PATH,
        repository_root=REPOSITORY_ROOT,
        events_root=events_root,
        action=action,
        reviewer_id="phase2-operator",
        nonce=nonce,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(hours=1),
    )
    state_path = tmp_path / f"{action}-state.json"
    request_path = tmp_path / f"{action}-request.json"
    _write(state_path, state.model_dump(mode="json"))
    _write(request_path, request.model_dump(mode="json"))
    context = capability.catalog_activation_issuance_context(
        request_path,
        state_path,
        approval_path=APPROVAL_PATH,
        events_root=events_root,
        repository_root=REPOSITORY_ROOT,
    )
    descriptor_path = tmp_path / f"{action}-authority.json"
    _write(
        descriptor_path,
        {
            "schema_version": "itda.catalog-activation-authority-descriptor.v2",
            "issuance_context": context.model_dump(mode="json"),
            "authority_token": context.expected_token().serialize(),
        },
    )
    return events_root, state_path, request_path, descriptor_path, state, request


def _consume(capability, tmp_path: Path, bundle, *, occurred_at: datetime = NOW):
    events_root, state_path, request_path, descriptor_path, _, _ = bundle
    return capability.consume_catalog_activation(
        authority_descriptor_path=descriptor_path,
        request_path=request_path,
        state_path=state_path,
        approval_path=APPROVAL_PATH,
        events_root=events_root,
        nonce_ledger_root=tmp_path / "ledger",
        repository_root=REPOSITORY_ROOT,
        occurred_at=occurred_at,
    )


def test_preflight_binds_none_to_exact_approved_revision_without_event(tmp_path: Path) -> None:
    capability = _capability()
    first = _bundle(capability, tmp_path)
    second = _bundle(capability, tmp_path / "second")
    events_root, state_path, request_path, _, state, request = first

    assert state.active_revision_sha256 is None
    assert state.current_event_sha256 is None
    assert state.current_sequence == 0
    assert request.action == "catalog-activate"
    assert request.current_revision_sha256 is None
    assert request.target_revision_sha256 == state.catalog_revision_sha256
    assert request.rollback_capability_sha256 == state.rollback_capability_sha256
    assert state.rollback_capability_sha256 == second[4].rollback_capability_sha256
    assert state.model_dump(mode="json") == second[4].model_dump(mode="json")
    assert request.model_dump(mode="json") == second[5].model_dump(mode="json")
    assert capability.check_catalog_activation_request(
        request_path,
        state_path,
        approval_path=APPROVAL_PATH,
        events_root=events_root,
        repository_root=REPOSITORY_ROOT,
    ).request_sha256 == request.request_sha256
    assert not events_root.exists()
    assert not (tmp_path / "catalog-activation-event.json").exists()


def test_activate_rollback_to_none_and_reactivate_are_hash_chained(tmp_path: Path) -> None:
    capability = _capability()
    approval_before = APPROVAL_PATH.read_bytes()
    revision_before = REVISION_PATH.read_bytes()

    activate = _bundle(capability, tmp_path, nonce="a" * 64)
    first = _consume(capability, tmp_path, activate, occurred_at=NOW)
    rollback = _bundle(
        capability,
        tmp_path,
        action="catalog-rollback",
        nonce="b" * 64,
        issued_at=NOW + timedelta(minutes=2),
    )
    second = _consume(
        capability,
        tmp_path,
        rollback,
        occurred_at=NOW + timedelta(minutes=3),
    )
    reactivate = _bundle(
        capability,
        tmp_path,
        nonce="c" * 64,
        issued_at=NOW + timedelta(minutes=4),
    )
    third = _consume(
        capability,
        tmp_path,
        reactivate,
        occurred_at=NOW + timedelta(minutes=5),
    )

    chain = capability.replay_catalog_activation_chain(activate[0])
    assert [event.action for event in chain.events] == [
        "catalog-activate",
        "catalog-rollback",
        "catalog-activate",
    ]
    assert first.to_revision_sha256 == first.catalog_revision_sha256
    assert second.from_revision_sha256 == first.catalog_revision_sha256
    assert second.to_revision_sha256 is None
    assert third.from_revision_sha256 is None
    assert third.to_revision_sha256 == first.catalog_revision_sha256
    assert second.previous_event_sha256 == first.event_sha256
    assert third.previous_event_sha256 == second.event_sha256
    assert chain.active_revision_sha256 == first.catalog_revision_sha256
    assert APPROVAL_PATH.read_bytes() == approval_before
    assert REVISION_PATH.read_bytes() == revision_before


def test_wrong_target_stale_head_replay_and_tampered_chain_fail_closed(
    tmp_path: Path,
) -> None:
    capability = _capability()
    activate = _bundle(capability, tmp_path)
    _, state_path, request_path, _, _, request = activate
    wrong = request.model_dump(mode="json")
    wrong["target_revision_sha256"] = "f" * 64
    wrong["request_sha256"] = None
    wrong_path = tmp_path / "wrong-request.json"
    _write(wrong_path, wrong)
    with pytest.raises(ValueError, match="target|request|approved|canonical"):
        capability.check_catalog_activation_request(
            wrong_path,
            state_path,
            approval_path=APPROVAL_PATH,
            events_root=activate[0],
            repository_root=REPOSITORY_ROOT,
        )

    event = _consume(capability, tmp_path, activate)
    with pytest.raises(
        (ValueError, AuthorityReplayError),
        match="stale|head|nonce|consumed|already active",
    ):
        _consume(capability, tmp_path, activate, occurred_at=NOW + timedelta(minutes=1))
    with pytest.raises(ValueError, match="stale|head|current|already active"):
        capability.check_catalog_activation_request(
            request_path,
            state_path,
            approval_path=APPROVAL_PATH,
            events_root=activate[0],
            repository_root=REPOSITORY_ROOT,
        )

    event_path = capability.catalog_activation_event_path(activate[0], event)
    tampered = json.loads(event_path.read_bytes())
    tampered["reviewer_id"] = "attacker"
    event_path.write_bytes(canonical_json_bytes(tampered))
    with pytest.raises(ValueError):
        capability.replay_catalog_activation_chain(activate[0])


def test_uncertain_append_is_recovered_without_duplicate_event(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability = _capability()
    activate = _bundle(capability, tmp_path)
    original = capability._append_event_locked
    tripped = False

    def uncertain(*args, **kwargs):
        nonlocal tripped
        event = original(*args, **kwargs)
        if not tripped:
            tripped = True
            raise AuthorityMutationUncertain("simulated crash after durable append")
        return event

    monkeypatch.setattr(capability, "_append_event_locked", uncertain)
    event = _consume(capability, tmp_path, activate)
    chain = capability.replay_catalog_activation_chain(activate[0])
    assert len(chain.events) == 1
    assert chain.events[0].event_sha256 == event.event_sha256
    receipts = (tmp_path / "ledger/authority-consumption-ledger.jsonl").read_text().splitlines()
    assert len(receipts) == 1
    assert json.loads(receipts[0])["completion"] == "RELOOKUP_CONFIRMED"


def test_concurrent_append_commits_exactly_one_event_and_receipt(tmp_path: Path) -> None:
    capability = _capability()
    activate = _bundle(capability, tmp_path)

    def submit(index: int):
        return _consume(
            capability,
            tmp_path,
            activate,
            occurred_at=NOW + timedelta(seconds=index),
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(submit, index) for index in range(8)]
    successes = []
    failures = []
    for future in futures:
        try:
            successes.append(future.result())
        except (ValueError, AuthorityReplayError) as exc:
            failures.append(exc)

    assert len(successes) == 1
    assert len(failures) == 7
    assert len(capability.replay_catalog_activation_chain(activate[0]).events) == 1
    receipts = (tmp_path / "ledger/authority-consumption-ledger.jsonl").read_text().splitlines()
    assert len(receipts) == 1


def test_verify_event_requires_current_head_and_cli_exposes_plan24_flags(
    tmp_path: Path,
) -> None:
    capability = _capability()
    activate = _bundle(capability, tmp_path)
    event = _consume(capability, tmp_path, activate)
    event_path = capability.catalog_activation_event_path(activate[0], event)
    verified = capability.verify_catalog_activation_event(
        event_path,
        events_root=activate[0],
        approval_path=APPROVAL_PATH,
        repository_root=REPOSITORY_ROOT,
        require_current=True,
    )
    assert verified.event_sha256 == event.event_sha256

    from itda.cli.activate_catalog import build_parser

    args = build_parser().parse_args(["--verify-event", str(event_path), "--require-current"])
    assert args.verify_event == event_path
    assert args.require_current is True
