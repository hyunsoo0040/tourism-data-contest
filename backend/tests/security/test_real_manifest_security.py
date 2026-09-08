"""Controlled release-boundary contract for the future real split owner."""

from __future__ import annotations

import importlib
import importlib.util
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from itda.cli.build_real_split import (
    build_materialization_authority,
    materialize_real_split,
    verify_materialized_bundle,
)
from itda.contracts.authority import AuthorityTokenV2
from itda.domain.canonical import canonical_json_bytes

RELEASE_MODULE = "itda.cli.build_real_split"


def test_missing_real_manifest_release_boundary_is_controlled_red() -> None:
    if importlib.util.find_spec(RELEASE_MODULE) is None:
        pytest.fail("PHASE2-MISSING:real-manifest-release-boundary", pytrace=False)
    importlib.import_module(RELEASE_MODULE)


def _feasible_candidate_bundle() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    from itda.cli.build_real_split import build_balance_outcome
    from tests.pipeline.test_real_split_determinism import _row, _singleton_components

    rows = tuple(
        _row(
            index,
            history=index <= 18,
            emotion=index % 3 == 0,
            rest=index % 4 == 0,
            completeness=index % 6,
        )
        for index in range(1, 37)
    )
    outcome = build_balance_outcome(rows, _singleton_components(rows), blind_size=12, seed=42)
    assert outcome.candidate is not None
    return (
        outcome.model_dump(mode="json"),
        outcome.candidate.model_dump(mode="json"),
        {
            "catalog_revision_sha256": "1" * 64,
            "catalog_activation_event_sha256": "2" * 64,
            "catalog_approval_sha256": "3" * 64,
            "authoritative_relationship_leaves_sha256": "4" * 64,
            "active_ordered_place_ids_sha256": "6" * 64,
        },
    )


def test_public_materialization_request_is_membership_free_and_digest_only() -> None:
    outcome, candidate, parents = _feasible_candidate_bundle()
    now = datetime(2026, 8, 1, 12, tzinfo=UTC)
    state, request = build_materialization_authority(
        outcome,
        candidate,
        active_parents=parents,
        reviewer_id="phase2-operator",
        nonce="5" * 64,
        issued_at=now,
        expires_at=now + timedelta(days=7),
    )
    serialized = json.dumps(request.model_dump(mode="json"), sort_keys=True).casefold()
    assert request.action == "real-split-materialize"
    assert state.status == "CANDIDATE_ONLY"
    assert "place:" not in serialized
    assert "members" not in serialized
    assert "balance_rows" not in serialized
    assert request.dev_count == 24 and request.blind_count == 12


def test_materialization_requires_exact_token_and_has_zero_output_without_it(
    tmp_path: Path,
) -> None:
    outcome, candidate, parents = _feasible_candidate_bundle()
    now = datetime(2026, 8, 1, 12, tzinfo=UTC)
    state, request = build_materialization_authority(
        outcome,
        candidate,
        active_parents=parents,
        reviewer_id="phase2-operator",
        nonce="5" * 64,
        issued_at=now,
        expires_at=now + timedelta(days=7),
    )
    with pytest.raises(ValueError):
        materialize_real_split(
            raw_token="",
            request=request,
            state=state,
            outcome=outcome,
            candidate=candidate,
            output_root=tmp_path / "split",
            nonce_ledger_root=tmp_path / "ledger",
            materialized_at=now,
        )
    assert not (tmp_path / "split").exists()


def test_atomic_materialization_success_replay_and_stale_target(tmp_path: Path) -> None:
    outcome, candidate, parents = _feasible_candidate_bundle()
    now = datetime(2026, 8, 1, 12, tzinfo=UTC)
    state, request = build_materialization_authority(
        outcome,
        candidate,
        active_parents=parents,
        reviewer_id="phase2-operator",
        nonce="5" * 64,
        issued_at=now,
        expires_at=now + timedelta(days=7),
    )
    token = AuthorityTokenV2(
        action=request.action,
        request_sha256=request.request_sha256,
        state_attestation_sha256=request.state_attestation_sha256,
        target_sha256=request.target_sha256,
        reviewer_id=request.reviewer_id,
        binding_sha256=request.binding_sha256,
        nonce=request.nonce,
    ).serialize()
    output = tmp_path / "split"
    first = materialize_real_split(
        raw_token=token,
        request=request,
        state=state,
        outcome=outcome,
        candidate=candidate,
        output_root=output,
        nonce_ledger_root=tmp_path / "ledger",
        materialized_at=now,
    )
    assert verify_materialized_bundle(output / "real-split-materialization-bundle.json") == first
    before = {path.name: path.read_bytes() for path in output.iterdir()}
    replay = materialize_real_split(
        raw_token=token,
        request=request,
        state=state,
        outcome=outcome,
        candidate=candidate,
        output_root=output,
        nonce_ledger_root=tmp_path / "ledger",
        materialized_at=now,
    )
    assert replay == first
    assert {path.name: path.read_bytes() for path in output.iterdir()} == before

    stale = request.model_dump(mode="json")
    stale["target_sha256"] = "0" * 64
    stale["request_sha256"] = None
    with pytest.raises(ValueError):
        materialize_real_split(
            raw_token=token,
            request=stale,
            state=state,
            outcome=outcome,
            candidate=candidate,
            output_root=tmp_path / "stale",
            nonce_ledger_root=tmp_path / "ledger-stale",
            materialized_at=now,
        )
    assert not (tmp_path / "stale").exists()


def test_materialized_outputs_are_restricted_canonical_and_do_not_approve_or_seal(
    tmp_path: Path,
) -> None:
    outcome, candidate, parents = _feasible_candidate_bundle()
    now = datetime(2026, 8, 1, 12, tzinfo=UTC)
    state, request = build_materialization_authority(
        outcome,
        candidate,
        active_parents=parents,
        reviewer_id="phase2-operator",
        nonce="5" * 64,
        issued_at=now,
        expires_at=now + timedelta(days=7),
    )
    token = request.expected_token().serialize()
    output = tmp_path / "split"
    materialize_real_split(
        raw_token=token,
        request=request,
        state=state,
        outcome=outcome,
        candidate=candidate,
        output_root=output,
        nonce_ledger_root=tmp_path / "ledger",
        materialized_at=now,
    )
    assert {path.name for path in output.iterdir()} == {
        "real-split-manifest.json",
        "real-split-determinism-report.json",
        "real-split-materialization-bundle.json",
    }
    for path in output.iterdir():
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.read_bytes() == canonical_json_bytes(json.loads(path.read_bytes()))
    manifest = json.loads((output / "real-split-manifest.json").read_bytes())
    assert manifest["status"] == "MATERIALIZED_UNAPPROVED"
    assert manifest["split_approval_sha256"] is None
    assert manifest["seal_sha256"] is None


def test_materialization_preserves_existing_split_root_and_commits_one_receipt(
    tmp_path: Path,
) -> None:
    outcome, candidate, parents = _feasible_candidate_bundle()
    now = datetime(2026, 8, 1, 12, tzinfo=UTC)
    state, request = build_materialization_authority(
        outcome,
        candidate,
        active_parents=parents,
        reviewer_id="phase2-operator",
        nonce="5" * 64,
        issued_at=now,
        expires_at=now + timedelta(days=7),
    )
    output = tmp_path / "split"
    output.mkdir(mode=0o700)
    preexisting = output / "real-split-candidate.json"
    preexisting.write_bytes(b"protected-parent")
    ledger = tmp_path / "ledger"

    materialize_real_split(
        raw_token=request.expected_token().serialize(),
        request=request,
        state=state,
        outcome=outcome,
        candidate=candidate,
        output_root=output,
        nonce_ledger_root=ledger,
        materialized_at=now,
    )

    assert preexisting.read_bytes() == b"protected-parent"
    assert {
        "real-split-manifest.json",
        "real-split-determinism-report.json",
        "real-split-materialization-bundle.json",
    }.issubset(path.name for path in output.iterdir())
    receipts = (ledger / "authority-consumption-ledger.jsonl").read_bytes().splitlines()
    assert len(receipts) == 1
    assert json.loads(receipts[0])["completion"] == "MUTATION_COMMITTED"
