from __future__ import annotations

import inspect
import os
import socket
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from itda.cli import collect_catalog_enrichment as collector_cli
from itda.cli.plan_catalog_kto_recovery import (
    build_kto_eligibility_generation,
    build_policy_decision_receipt,
    build_traffic_free_preflight,
)
from itda.contracts.catalog_enrichment import (
    build_kto_recovery_request,
    canonical_json_bytes,
)
from itda.contracts.catalog_grammar_successor import (
    classify_typed_intro_recovery,
)

REPOSITORY_ROOT = Path(__file__).parents[3]
DECISION_ROOT = (
    REPOSITORY_ROOT
    / "artifacts/restricted/catalog/v2/supplemental/kto-recovery/decisions"
    / "d14f733655b846b08f2f058bd05ac0615956f8c8124524f45fc0e52b34f17084"
)
FORBIDDEN_OUTPUTS = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/supplemental/kto-recovery/decisions",
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/supplemental/kto-recovery/eligibility",
)


def test_plan49_normalization_interface_is_offline_and_secret_free() -> None:
    from itda.cli import normalize_catalog_enrichment as normalizer

    parser = normalizer.kto_recovery_parser()
    options = {option for action in parser._actions for option in action.option_strings}
    prohibited = {
        "--credential-file",
        "--authority-file",
        "--authority-stdin",
        "--nonce",
        "--service-key",
        "--url",
        "--collection-root",
    }
    assert options.isdisjoint(prohibited)
    source = Path(normalizer.__file__).read_text(encoding="utf-8")
    assert ".secrets/itda-api.env" not in source
    assert "httpx" not in source
    assert "requests." not in source
    assert "socket." not in source


def test_plan49_readiness_interface_cannot_issue_authority_or_select_membership() -> None:
    from itda.cli import audit_catalog_readiness as readiness_cli

    parser = readiness_cli.kto_recovery_parser()
    options = {option for action in parser._actions for option in action.option_strings}
    prohibited = {
        "--credential-file",
        "--authority-file",
        "--authority-stdin",
        "--nonce",
        "--service-key",
        "--collection-root",
        "--target-count",
        "--universe-count",
        "--candidate-id",
        "--canonical",
        "--split",
    }
    assert options.isdisjoint(prohibited)
    source = inspect.getsource(readiness_cli.build_kto_recovery_readiness)
    assert "httpx" not in source
    assert "requests." not in source
    assert "socket." not in source
    assert "authority" not in source.lower()
    assert "nonce" not in source.lower()


def test_plan49_terminal_rejection_is_offline_and_non_capability_bearing() -> None:
    from itda.cli import audit_catalog_readiness as readiness_cli

    source = inspect.getsource(readiness_cli.build_kto_recovery_terminal_failure)
    assert ".secrets/itda-api.env" not in source
    assert "httpx" not in source
    assert "requests." not in source
    assert "socket." not in source
    assert "collect_kto_recovery_packet" not in source


def test_preflight_has_no_network_or_mutating_side_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = tuple(path.exists() for path in FORBIDDEN_OUTPUTS)

    def blocked_socket(*_args: object, **_kwargs: object) -> socket.socket:
        raise AssertionError("traffic-free KTO preflight attempted network access")

    monkeypatch.setattr(socket, "socket", blocked_socket)
    packet = build_traffic_free_preflight(REPOSITORY_ROOT)

    assert packet["status"] == "AWAITING_EXACT_HUMAN_DECISION"
    assert tuple(path.exists() for path in FORBIDDEN_OUTPUTS) == before


def test_typed_intro_success_empty_and_semantic_successor_stay_ineligible() -> None:
    predecessor = {
        "operation": "detailIntro2",
        "provider_result_code": "0000",
        "provider_result_value": "OK",
        "deficit_reason": "SUCCESS_RESPONSE_FIELD_EMPTY",
        "requested_content_type_id": "12",
        "actual_content_type_id": "14",
    }
    assert classify_typed_intro_recovery(predecessor) == {
        "reinforcement_18_eligibility": "INELIGIBLE",
        "semantic_successor_eligibility": "INELIGIBLE",
        "permitted_resolution": "EXACT_KTO_TARGET_SUBSTITUTION_OR_STOP",
    }


@pytest.mark.parametrize(
    "forbidden_key",
    [
        "serviceKey",
        "service_key",
        "apiKey",
        "authorization",
        "nonce",
        "authority_token",
        "canonical_membership",
        "split_membership",
        "seal",
    ],
)
def test_secret_authority_and_downstream_fields_are_unrepresentable(
    forbidden_key: str,
) -> None:
    packet = build_traffic_free_preflight(REPOSITORY_ROOT)

    def keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value) | {nested for child in value.values() for nested in keys(child)}
        if isinstance(value, list):
            return {nested for child in value for nested in keys(child)}
        return set()

    assert forbidden_key not in keys(packet)


def test_request_identity_rejects_legacy_switches_and_caller_type_patch() -> None:
    request = build_kto_recovery_request(
        operation="detailCommon2",
        provider_candidate_id="candidate:tour-api:123",
        place_entity_id="place:" + "a" * 64,
        source_candidate_row_sha256="b" * 64,
    )
    assert "addrinfoYN" not in request["parameters"]
    assert "contentTypeId" not in request["parameters"]
    assert "subImageYN" not in request["parameters"]


@pytest.mark.parametrize(
    "rationale",
    [
        "read serviceKey from disk",
        "issue authority for Plan 48",
        "reuse nonce",
        "change schema",
        "select canonical membership",
        "waive split gate",
        "seal now",
    ],
)
def test_policy_receipt_rejects_external_or_downstream_instructions(
    rationale: str,
) -> None:
    preflight = build_traffic_free_preflight(REPOSITORY_ROOT)
    with pytest.raises(ValueError, match="prohibited instruction"):
        build_policy_decision_receipt(
            preflight,
            selected_policy="require-kto-substitution",
            reviewer_id="phase2-operator",
            rationale=rationale,
        )


def test_final_packet_excludes_intro_predecessors_secrets_and_authority() -> None:
    generation = build_kto_eligibility_generation(REPOSITORY_ROOT, DECISION_ROOT)
    payload = b"".join(generation.files.values())
    request_manifest = generation.json_value("request-manifest.json")

    assert b"serviceKey" not in payload
    assert b"authority_token" not in payload
    assert b'"nonce"' not in payload
    assert b"canonical_membership" not in payload
    assert b"split_membership" not in payload
    assert all(
        row["provider_candidate_id"]
        not in {
            "candidate:tour-api:3486762",
            "candidate:tour-api:3056660",
            "candidate:tour-api:3032546",
        }
        for row in request_manifest["requests"]
    )
    assert len({row["request_identity"] for row in request_manifest["requests"]}) == 48


def test_collector_has_no_authority_issuer_or_value_taking_cli_option() -> None:
    source = inspect.getsource(collector_cli)
    parser = collector_cli.parser()
    options = {option for action in parser._actions for option in action.option_strings}

    assert "--authorization-token" not in options
    assert "freeze_issuance_context(" not in source
    assert "AuthorityTokenV2(" not in source
    assert ".serialize()" not in source


def test_credential_symlink_and_wrong_mode_fail_before_socket_or_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = tmp_path / "real.env"
    real.write_text("TOUR_API_SERVICE_KEY=fixture-secret\n", encoding="utf-8")
    real.chmod(0o600)
    link = tmp_path / "link.env"
    link.symlink_to(real)
    collections = tmp_path / "collections"
    monkeypatch.setattr(collector_cli, "KTO_COLLECTIONS_BASE", collections)

    class NoTraffic:
        def stream(self, *_args: object, **_kwargs: object) -> Any:
            raise AssertionError("invalid credential path reached transport")

    preflight = collector_cli.build_kto_collection_preflight(
        REPOSITORY_ROOT,
        issued_at=datetime(2026, 7, 30, 14, 30, tzinfo=UTC),
        deadline=datetime(2026, 7, 31, 14, 30, tzinfo=UTC),
        reviewer_id="phase2-operator",
    )
    context = collector_cli.derive_kto_authority_context(
        preflight,
        nonce="9" * 64,
    )
    token = context.expected_token().serialize()

    with pytest.raises(ValueError, match="symlink|regular"):
        collector_cli.collect_kto_recovery_packet(
            REPOSITORY_ROOT,
            authorization_token=token,
            credential_path=link,
            issued_at=datetime(2026, 7, 30, 14, 30, tzinfo=UTC),
            deadline=datetime(2026, 7, 31, 14, 30, tzinfo=UTC),
            reviewer_id="phase2-operator",
            now=datetime(2026, 7, 30, 14, 30, tzinfo=UTC),
            requester=NoTraffic(),
        )
    assert not collections.exists()

    real.chmod(0o644)
    with pytest.raises(ValueError, match="0600"):
        collector_cli.collect_kto_recovery_packet(
            REPOSITORY_ROOT,
            authorization_token=token,
            credential_path=real,
            issued_at=datetime(2026, 7, 30, 14, 30, tzinfo=UTC),
            deadline=datetime(2026, 7, 31, 14, 30, tzinfo=UTC),
            reviewer_id="phase2-operator",
            now=datetime(2026, 7, 30, 14, 30, tzinfo=UTC),
            requester=NoTraffic(),
        )
    assert not collections.exists()


def test_preflight_rejects_root_discovery_drift_before_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collections = tmp_path / "collections"
    monkeypatch.setattr(collector_cli, "KTO_COLLECTIONS_BASE", collections)

    def drifted(*_args: object, **_kwargs: object) -> Path:
        raise ValueError("expected exactly one direct KTO eligibility success root")

    monkeypatch.setattr(
        collector_cli,
        "discover_exact_kto_eligibility_success",
        drifted,
    )
    with pytest.raises(ValueError, match="exactly one"):
        collector_cli.build_kto_collection_preflight(
            REPOSITORY_ROOT,
            issued_at=datetime(2026, 7, 30, 14, 30, tzinfo=UTC),
            deadline=datetime(2026, 7, 31, 14, 30, tzinfo=UTC),
            reviewer_id="phase2-operator",
        )
    assert not collections.exists()


def test_preflight_and_collector_never_read_default_credential_or_open_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def blocked_open(*_args: object, **_kwargs: object) -> int:
        raise AssertionError("preflight attempted credential access")

    def blocked_socket(*_args: object, **_kwargs: object) -> socket.socket:
        raise AssertionError("preflight attempted provider traffic")

    monkeypatch.setattr(collector_cli, "_read_kto_credential", blocked_open)
    monkeypatch.setattr(socket, "socket", blocked_socket)
    preflight = collector_cli.build_kto_collection_preflight(
        REPOSITORY_ROOT,
        issued_at=datetime(2026, 7, 30, 14, 30, tzinfo=UTC),
        deadline=datetime(2026, 7, 31, 14, 30, tzinfo=UTC),
        reviewer_id="phase2-operator",
    )
    assert preflight["request_count"] == 48
    assert ".itda-api.env" not in canonical_json_bytes(preflight).decode("utf-8")


def test_process_arguments_cannot_carry_authority_or_credential_value() -> None:
    parser = collector_cli.parser()
    options = {option for action in parser._actions for option in action.option_strings}
    assert "--authorization-token" not in options
    assert "--credential-value" not in options
    assert "TOUR_API_SERVICE_KEY" not in " ".join(os.sys.argv)


def test_kto_seal_interface_has_no_secret_bearing_option_or_mutable_pointer() -> None:
    parser = collector_cli.kto_recovery_parser()
    options = {option for action in parser._actions for option in action.option_strings}

    assert "--verify-kto-recovery" in options
    assert "--discover-exact-success-under" in options
    assert "--authorization-token" not in options
    assert "--credential-value" not in options
    assert "--collection-root" not in options
