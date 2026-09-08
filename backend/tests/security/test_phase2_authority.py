"""Hostile security contract for the shared Phase 2 authority-v2 boundary."""

from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from itda.contracts.authority import (
    ALLOWED_AUTHORITY_ACTIONS,
    AuthorityMutationUncertain,
    AuthorityReplayError,
    AuthorityRevocationTombstone,
    AuthorityTokenV2,
    FileNonceLedger,
    freeze_issuance_context,
    validate_authority_token,
)

HEX = "a" * 64
NOW = datetime(2026, 7, 28, 17, 0, tzinfo=UTC)


def _parents(suffix: str = "") -> dict[str, object]:
    return {
        "request": {"schema_version": "request-v1", "scope": f"scope{suffix}"},
        "state": {"schema_version": "state-v1", "head": f"head{suffix}"},
        "target": {"schema_version": "target-v1", "result": f"result{suffix}"},
        "binding": {
            "schema_version": "binding-v1",
            "round_id": hashlib.sha256(f"round{suffix}".encode()).hexdigest(),
        },
    }


def _context(*, suffix: str = "", nonce: str = HEX):
    parents = _parents(suffix)
    return freeze_issuance_context(
        action="enrichment-collect",
        request=parents["request"],
        state_attestation=parents["state"],
        target=parents["target"],
        reviewer_id="local-reviewer_01",
        binding=parents["binding"],
        nonce=nonce,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=20),
        reviewer_channel_risk=(
            "Single-operator local authenticated channel; reviewer identity is not "
            "cryptographically proven."
        ),
    )


def _validate(context, *, parents: dict[str, object] | None = None):
    source = parents or _parents()
    return validate_authority_token(
        context.expected_token().serialize(),
        issuance_context=context,
        request=source["request"],
        state_attestation=source["state"],
        target=source["target"],
        binding=source["binding"],
        reviewer_id=context.reviewer_id,
        now=NOW + timedelta(minutes=1),
        revocation_tombstones=(),
    )


def test_strict_seven_field_v2_grammar_and_allowed_actions() -> None:
    context = _context()
    token = context.expected_token()
    serialized = token.serialize()

    assert serialized.startswith("itda-auth-v2:enrichment-collect:")
    assert serialized.count(":") == 7
    assert AuthorityTokenV2.parse(serialized) == token
    assert token.action in ALLOWED_AUTHORITY_ACTIONS
    assert "itda-auth-v2" not in repr(token)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.replace("itda-auth-v2", "itda-auth-v1", 1),
        lambda value: value.replace("enrichment-collect", "unknown-action", 1),
        lambda value: value + ":extra",
        lambda value: value.rsplit(":", 1)[0],
        lambda value: value.replace("a" * 64, "A" * 64, 1),
        lambda value: value.replace("local-reviewer_01", "local reviewer", 1),
        lambda value: " " + value,
        lambda value: value.replace("local-reviewer_01", "ｌocal-reviewer_01", 1),
    ],
    ids=[
        "v1",
        "unknown-action",
        "extra-field",
        "missing-field",
        "uppercase-hex",
        "whitespace",
        "leading-space",
        "unicode-normalization",
    ],
)
def test_parser_rejects_noncanonical_or_malformed_tokens(mutate) -> None:
    serialized = _context().expected_token().serialize()
    with pytest.raises(ValueError):
        AuthorityTokenV2.parse(mutate(serialized))


@pytest.mark.parametrize(
    "field",
    [
        "request",
        "state",
        "target",
        "binding",
    ],
)
def test_every_parent_field_is_independently_rederived_without_consumption(field: str) -> None:
    context = _context()
    drifted = _parents()
    drifted[field] = {**drifted[field], "drift": True}

    with pytest.raises(ValueError, match=field.replace("_attestation", "") + "|digest|stale"):
        _validate(context, parents=drifted)


def test_mixed_fields_from_two_valid_requests_are_rejected() -> None:
    first = _context()
    second = _context(suffix="-other", nonce="b" * 64)
    parents = _parents()
    mixed = first.expected_token().model_copy(
        update={
            "state_attestation_sha256": second.state_attestation_sha256,
            "target_sha256": second.target_sha256,
        }
    ).serialize()

    with pytest.raises(ValueError, match="state|target|field|stale"):
        validate_authority_token(
            mixed,
            issuance_context=first,
            reviewer_id=first.reviewer_id,
            now=NOW + timedelta(minutes=1),
            revocation_tombstones=(),
            request=parents["request"],
            state_attestation=parents["state"],
            target=parents["target"],
            binding=parents["binding"],
        )


def test_validation_does_not_consume_nonce_and_expiry_or_revocation_blocks() -> None:
    context = _context()
    parents = _parents()
    first = _validate(context)
    second = _validate(context)
    assert first == second

    with pytest.raises(ValueError, match="expired"):
        validate_authority_token(
            context.expected_token().serialize(),
            issuance_context=context,
            reviewer_id=context.reviewer_id,
            now=context.expires_at,
            revocation_tombstones=(),
            request=parents["request"],
            state_attestation=parents["state"],
            target=parents["target"],
            binding=parents["binding"],
        )

    tombstone = AuthorityRevocationTombstone.for_context(
        context,
        revoked_at=NOW + timedelta(seconds=30),
        reason_code="REQUEST_REPLACED",
        replacement_request_sha256="f" * 64,
    )
    with pytest.raises(ValueError, match="revoked|tombstone"):
        validate_authority_token(
            context.expected_token().serialize(),
            issuance_context=context,
            reviewer_id=context.reviewer_id,
            now=NOW + timedelta(minutes=1),
            revocation_tombstones=(tombstone,),
            request=parents["request"],
            state_attestation=parents["state"],
            target=parents["target"],
            binding=parents["binding"],
        )


def test_nonce_is_consumed_once_globally_with_mutation(tmp_path: Path) -> None:
    context = _context()
    validated = _validate(context)
    ledger = FileNonceLedger(tmp_path / "authority-ledger")
    output = tmp_path / "committed-result"

    def submit(index: int):
        def mutation() -> dict[str, object]:
            output.mkdir()
            (output / "owner.txt").write_text(str(index), encoding="utf-8")
            return {"result_sha256": hashlib.sha256(str(index).encode()).hexdigest()}

        return ledger.consume_with_mutation(validated, mutation=mutation)

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(submit, index) for index in range(8)]

    receipts = []
    replays = 0
    for future in futures:
        try:
            receipts.append(future.result())
        except AuthorityReplayError:
            replays += 1

    assert len(receipts) == 1
    assert replays == 7
    assert output.is_dir()
    receipt = receipts[0]
    assert receipt.token_sha256 == hashlib.sha256(
        context.expected_token().serialize().encode("ascii")
    ).hexdigest()
    assert "itda-auth-v2" not in receipt.model_dump_json()
    assert context.nonce not in receipt.model_dump_json()


def test_uncertain_result_is_relooked_up_without_second_mutation(tmp_path: Path) -> None:
    context = _context()
    validated = _validate(context)
    ledger = FileNonceLedger(tmp_path / "authority-ledger")
    output = tmp_path / "result.json"
    mutation_calls = 0

    def mutation() -> dict[str, object]:
        nonlocal mutation_calls
        mutation_calls += 1
        output.write_text('{"status":"committed"}', encoding="utf-8")
        raise AuthorityMutationUncertain("connection dropped after durable publication")

    receipt = ledger.consume_with_mutation(
        validated,
        mutation=mutation,
        relookup=lambda: {
            "result_sha256": hashlib.sha256(output.read_bytes()).hexdigest()
        }
        if output.exists()
        else None,
    )

    assert mutation_calls == 1
    assert receipt.completion == "RELOOKUP_CONFIRMED"
    with pytest.raises(AuthorityReplayError):
        ledger.consume_with_mutation(validated, mutation=lambda: {})
