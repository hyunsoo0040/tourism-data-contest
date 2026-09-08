"""Network-disabled catalog remediation preflight contracts."""

from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from itda.cli.plan_catalog_remediation import (
    INSUFFICIENT_CONFIRMED_COVERAGE,
    PreflightError,
    _parser,
    derive_preflight_generation,
    publish_preflight_generation,
    verify_exact_success_under,
)
from itda.contracts.catalog_remediation_preflight import (
    SOURCE_PRIORITY,
    ConfirmedCoverageBound,
    OfficialSourceCapability,
    PacketManifest,
    PredeclaredLocalCapture,
    RecordAvailabilityState,
    SourceCapabilityState,
    TargetRow,
    build_confirmed_coverage_bound,
    build_packet_manifest,
    build_source_plan,
    build_target_matrix,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

REPO_ROOT = Path(__file__).parents[3]


def _target(
    marker: int,
    group: str,
    deficits: tuple[str, ...],
    *,
    capture: PredeclaredLocalCapture | None = None,
) -> TargetRow:
    return TargetRow(
        place_entity_id=f"place:{marker:064x}",
        existing_provider_candidate_id=f"candidate:tour-api:{100000 + marker}",
        primary_coverage_group=group,
        mandatory_deficits=deficits,
        mandatory_deficit_count=len(deficits),
        under_target_group_need=6,
        proposed_source_ids=SOURCE_PRIORITY,
        required_fields=tuple(
            field
            for deficit in deficits
            for field in {
                "DESCRIPTION_MISSING": ("korean_description",),
                "DIRECT_MEDIA_MISSING": (
                    "media_url",
                    "media_creator",
                    "media_license",
                ),
                "OPERATING_INFO_MISSING": ("operating_information",),
            }[deficit]
        ),
        record_availability=(
            RecordAvailabilityState.EXACT_LOCAL_ID_MATCH
            if capture is not None
            else RecordAvailabilityState.RECORD_AVAILABILITY_UNVERIFIED
        ),
        predeclared_capture=capture,
        confidence_adds_score=False,
        canonical_membership_created=False,
        split_membership_created=False,
    )


def _frontier(
    *,
    captures: dict[int, PredeclaredLocalCapture] | None = None,
) -> tuple[TargetRow, ...]:
    captures = captures or {}
    rows: list[TargetRow] = []
    marker = 1
    for _ in range(12):
        rows.append(
            _target(
                marker,
                "history_culture",
                ("DESCRIPTION_MISSING", "DIRECT_MEDIA_MISSING"),
                capture=captures.get(marker),
            )
        )
        marker += 1
    for _ in range(6):
        rows.append(
            _target(
                marker,
                "history_scenery_boundary",
                ("DESCRIPTION_MISSING", "DIRECT_MEDIA_MISSING"),
                capture=captures.get(marker),
            )
        )
        marker += 1
    for _ in range(3):
        rows.append(
            _target(
                marker,
                "image_modern_content",
                ("DESCRIPTION_MISSING", "DIRECT_MEDIA_MISSING"),
                capture=captures.get(marker),
            )
        )
        marker += 1
    for _ in range(3):
        rows.append(
            _target(
                marker,
                "image_modern_content",
                ("OPERATING_INFO_MISSING",),
                capture=captures.get(marker),
            )
        )
        marker += 1
    return tuple(rows)


def _capture(
    tmp_path: Path,
    marker: int,
    fields: tuple[str, ...],
) -> PredeclaredLocalCapture:
    relpath = f"artifacts/restricted/catalog/v2/supplemental/preflight-inputs/{marker}.json"
    payload = canonical_json_bytes(
        {
            "official_dataset_id": "15114464",
            "official_record_id": f"record-{marker}",
            "place_entity_id": f"place:{marker:064x}",
            "fields": {field: f"value-{marker}-{field}" for field in fields},
        }
    )
    capture_path = tmp_path / relpath
    capture_path.parent.mkdir(parents=True, exist_ok=True)
    capture_path.write_bytes(payload)
    return PredeclaredLocalCapture(
        repository_relative_path=relpath,
        file_sha256=canonical_sha256(json.loads(payload)),
        official_source_id="15114464",
        official_record_or_page_id=f"record-{marker}",
        place_entity_id=f"place:{marker:064x}",
        present_required_fields=fields,
        supplied_before_preflight=True,
        import_disposition="PREDECLARED_CAPTURE_REQUIRES_PLAN39_RIGHTS_VERIFICATION",
    )


def test_epistemic_states_are_closed_distinct_and_non_aliasing() -> None:
    assert SourceCapabilityState.RESEARCH_RECORDED_CAPABILITY != (
        SourceCapabilityState.SCHEMA_CAPABLE
    )
    assert RecordAvailabilityState.RECORD_AVAILABILITY_UNVERIFIED != (
        RecordAvailabilityState.EXACT_LOCAL_ID_MATCH
    )
    assert len(
        {
            SourceCapabilityState.RESEARCH_RECORDED_CAPABILITY.value,
            SourceCapabilityState.SCHEMA_CAPABLE.value,
            RecordAvailabilityState.RECORD_AVAILABILITY_UNVERIFIED.value,
            RecordAvailabilityState.EXACT_LOCAL_ID_MATCH.value,
            RecordAvailabilityState.REVIEW_REQUIRED.value,
            RecordAvailabilityState.UNAVAILABLE.value,
        }
    ) == 6

    capability = OfficialSourceCapability(
        source_priority=0,
        official_source_id="15114464",
        official_source_url="https://www.data.go.kr/data/15114464/openapi.do",
        capability_state=SourceCapabilityState.SCHEMA_CAPABLE,
        documented_fields=("korean_description", "media_url"),
        research_file_sha256="a" * 64,
        research_date="2026-07-30",
        refreshed_during_preflight=False,
        proves_record_availability=False,
        proves_rights=False,
    )
    assert capability.proves_record_availability is False
    assert capability.proves_rights is False


def test_capability_priority_is_exact_and_schema_never_confirms_a_record() -> None:
    assert SOURCE_PRIORITY == ("15114464", "15109381", "3070426")
    with pytest.raises(ValidationError, match="priority"):
        OfficialSourceCapability(
            source_priority=1,
            official_source_id="15114464",
            official_source_url="https://www.data.go.kr/data/15114464/openapi.do",
            capability_state=SourceCapabilityState.SCHEMA_CAPABLE,
            documented_fields=("korean_description",),
            research_file_sha256="a" * 64,
            research_date="2026-07-30",
            refreshed_during_preflight=False,
            proves_record_availability=False,
            proves_rights=False,
        )


def test_target_matrix_is_exact_24_row_12_6_6_vector_and_score_free() -> None:
    matrix = build_target_matrix(
        frontier=_frontier(),
        ordered_ancestry=("a" * 64, "b" * 64, "c" * 64, "d" * 64),
        attempted_provider_ids=(),
        terminal_eligible_group_counts={
            "history_culture": 0,
            "history_scenery_boundary": 0,
            "image_modern_content": 0,
            "rest_walk_immersion": 13,
        },
        terminal_objective_eligible_count=13,
    )

    assert matrix.target_count == 24
    assert matrix.addition_vector == {
        "history_culture": 12,
        "history_scenery_boundary": 6,
        "image_modern_content": 6,
        "rest_walk_immersion": 0,
    }
    assert sum(
        row.mandatory_deficits
        == ("DESCRIPTION_MISSING", "DIRECT_MEDIA_MISSING")
        for row in matrix.rows
    ) == 21
    assert sum(
        row.mandatory_deficits == ("OPERATING_INFO_MISSING",)
        for row in matrix.rows
    ) == 3
    dumped = json.dumps(matrix.model_dump(mode="json"), sort_keys=True)
    for forbidden in (
        '"score"',
        "popularity",
        "model_output",
        '"split_membership":',
        '"canonical_membership":',
    ):
        assert forbidden not in dumped
    assert matrix.confidence_adds_score is False


def test_frontier_excludes_attempted_provider_ids_before_vector_selection() -> None:
    frontier = _frontier()
    attempted = (frontier[0].existing_provider_candidate_id,)
    with pytest.raises(ValueError, match="fixed 12/6/6"):
        build_target_matrix(
            frontier=frontier,
            ordered_ancestry=("a" * 64, "b" * 64, "c" * 64, "d" * 64),
            attempted_provider_ids=attempted,
            terminal_eligible_group_counts={
                "history_culture": 0,
                "history_scenery_boundary": 0,
                "image_modern_content": 0,
                "rest_walk_immersion": 13,
            },
            terminal_objective_eligible_count=13,
        )


def test_confirmed_floor_requires_predeclared_path_hash_identity_and_all_fields(
    tmp_path: Path,
) -> None:
    fields = (
        "korean_description",
        "media_url",
        "media_creator",
        "media_license",
    )
    captures = {marker: _capture(tmp_path, marker, fields) for marker in range(1, 22)}
    captures.update(
        {
            marker: _capture(tmp_path, marker, ("operating_information",))
            for marker in range(22, 25)
        }
    )
    matrix = build_target_matrix(
        frontier=_frontier(captures=captures),
        ordered_ancestry=("a" * 64, "b" * 64, "c" * 64, "d" * 64),
        attempted_provider_ids=(),
        terminal_eligible_group_counts={
            "history_culture": 0,
            "history_scenery_boundary": 0,
            "image_modern_content": 0,
            "rest_walk_immersion": 13,
        },
        terminal_objective_eligible_count=13,
    )
    bound = build_confirmed_coverage_bound(matrix=matrix, repo_root=tmp_path)

    assert bound.confirmed_target_count == 24
    assert bound.confirmed_projected_total == 37
    assert bound.confirmed_group_counts == {
        "history_culture": 12,
        "history_scenery_boundary": 6,
        "image_modern_content": 6,
        "rest_walk_immersion": 13,
    }
    assert bound.confirmed_capped_sum == 36
    assert bound.all_target_deficits_serviceable is True
    assert bound.representation_feasible is True

    bad_payload = matrix.model_dump(mode="json")
    bad_payload["rows"][0]["predeclared_capture"]["file_sha256"] = "f" * 64
    bad_payload["matrix_sha256"] = canonical_sha256(
        {key: value for key, value in bad_payload.items() if key != "matrix_sha256"}
    )
    bad_matrix = type(matrix).model_validate(bad_payload)
    with pytest.raises(ValueError, match="capture hash"):
        build_confirmed_coverage_bound(matrix=bad_matrix, repo_root=tmp_path)


def test_schema_capability_only_produces_zero_confirmed_floor() -> None:
    matrix = build_target_matrix(
        frontier=_frontier(),
        ordered_ancestry=("a" * 64, "b" * 64, "c" * 64, "d" * 64),
        attempted_provider_ids=(),
        terminal_eligible_group_counts={
            "history_culture": 0,
            "history_scenery_boundary": 0,
            "image_modern_content": 0,
            "rest_walk_immersion": 13,
        },
        terminal_objective_eligible_count=13,
    )
    bound = build_confirmed_coverage_bound(matrix=matrix, repo_root=Path.cwd())

    assert bound.confirmed_target_count == 0
    assert bound.confirmed_projected_total == 13
    assert bound.confirmed_group_counts["rest_walk_immersion"] == 13
    assert bound.confirmed_capped_sum == 12
    assert bound.all_target_deficits_serviceable is False
    assert bound.representation_feasible is False
    assert bound.outcome == "INSUFFICIENT_CONFIRMED_COVERAGE"


def test_source_plan_is_unrepresentable_without_every_confirmed_predicate() -> None:
    payload = {
        "schema_version": "itda.catalog-confirmed-coverage-bound.v1",
        "schema_capable_target_count": 24,
        "confirmed_target_count": 0,
        "terminal_objective_eligible_count": 13,
        "confirmed_projected_total": 13,
        "confirmed_group_counts": {
            "history_culture": 0,
            "history_scenery_boundary": 0,
            "image_modern_content": 0,
            "rest_walk_immersion": 13,
        },
        "confirmed_capped_sum": 12,
        "target_serviceability": tuple(False for _ in range(24)),
        "all_target_deficits_serviceable": False,
        "representation_feasible": False,
        "rights_status": "PENDING_PLAN39_VERIFICATION",
        "outcome": "INSUFFICIENT_CONFIRMED_COVERAGE",
    }
    payload["bound_sha256"] = canonical_sha256(payload)
    insufficient = ConfirmedCoverageBound.model_validate(payload)
    with pytest.raises(ValueError, match="confirmed coverage"):
        build_source_plan(targets=_frontier(), coverage=insufficient)

    feasible_payload = {
        **payload,
        "confirmed_target_count": 24,
        "confirmed_projected_total": 37,
        "confirmed_group_counts": {
            "history_culture": 12,
            "history_scenery_boundary": 6,
            "image_modern_content": 6,
            "rest_walk_immersion": 13,
        },
        "confirmed_capped_sum": 36,
        "target_serviceability": tuple(True for _ in range(24)),
        "all_target_deficits_serviceable": True,
        "representation_feasible": True,
        "outcome": "FEASIBLE",
    }
    feasible_payload["bound_sha256"] = canonical_sha256(
        {key: value for key, value in feasible_payload.items() if key != "bound_sha256"}
    )
    feasible = ConfirmedCoverageBound.model_validate(feasible_payload)
    source_plan = build_source_plan(targets=_frontier(), coverage=feasible)
    assert {
        request.official_source_id
        for request in source_plan.requests
        if request.operation_or_page_kind == "attraction-status-record"
    } == {"15109381"}


def test_packet_manifest_is_non_circular_self_excluding_and_tamper_evident() -> None:
    packet = build_packet_manifest(
        ordered_child_digests=(
            ("official-source-metadata-manifest.json", "a" * 64),
            ("supplemental-target-matrix.json", "b" * 64),
            ("coverage-upper-bound.json", "c" * 64),
            ("preflight-state-attestation.json", "d" * 64),
            ("supplemental-round-manifest.json", "e" * 64),
        ),
        ordered_parents=("1" * 64, "2" * 64, "3" * 64, "4" * 64),
        policy_identities=("5" * 64, "6" * 64),
        confirmed_facts_sha256="7" * 64,
        round_id="8" * 64,
        publication_state="FAILURE",
    )
    assert tuple(packet.model_dump(mode="json")) == ("payload", "root_sha256")
    dumped = json.dumps(packet.payload, sort_keys=True)
    assert "packet_manifest_sha256" not in dumped
    assert "root_sha256" not in dumped
    assert "self" not in dumped
    assert packet.root_sha256 == canonical_sha256(packet.payload)

    tampered = packet.model_dump(mode="json")
    tampered["payload"]["publication_state"] = "SUCCESS"
    with pytest.raises(ValidationError, match="root"):
        PacketManifest.model_validate(tampered)


def test_cli_surface_is_network_credential_and_authority_free() -> None:
    help_text = _parser().format_help()
    for forbidden in (
        "--url",
        "--endpoint",
        "--credential",
        "--api-key",
        "--token",
        "--authority",
        "--download",
        "--fetch",
        "--schema-refresh",
        "--provider-execute",
    ):
        assert forbidden not in help_text
    assert "--round-root" in help_text
    assert "--round-id" in help_text
    assert "--require-confirmed-coverage" in help_text


def test_actual_preflight_is_byte_stable_network_disabled_and_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def blocked(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("network, DNS, or subprocess execution attempted")

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(subprocess, "run", blocked)
    monkeypatch.setattr(subprocess, "Popen", blocked)

    first = derive_preflight_generation(REPO_ROOT)
    second = derive_preflight_generation(REPO_ROOT)

    assert first.exit_code == INSUFFICIENT_CONFIRMED_COVERAGE
    assert first.round_id == second.round_id
    assert first.children == second.children
    assert first.round_manifest == second.round_manifest
    assert first.coverage.confirmed_target_count == 0
    assert first.coverage.confirmed_projected_total == 13
    assert first.coverage.confirmed_group_counts == {
        "history_culture": 0,
        "history_scenery_boundary": 0,
        "image_modern_content": 0,
        "rest_walk_immersion": 13,
    }
    assert first.coverage.confirmed_capped_sum == 12
    assert first.coverage.representation_feasible is False
    assert first.target_matrix.target_count == 24
    assert first.target_matrix.addition_vector == {
        "history_culture": 12,
        "history_scenery_boundary": 6,
        "image_modern_content": 6,
        "rest_walk_immersion": 0,
    }
    assert sum(
        row.mandatory_deficits
        == ("DESCRIPTION_MISSING", "DIRECT_MEDIA_MISSING")
        for row in first.target_matrix.rows
    ) == 21
    assert sum(
        row.mandatory_deficits == ("OPERATING_INFO_MISSING",)
        for row in first.target_matrix.rows
    ) == 3
    assert "supplemental-source-plan.json" not in first.children
    assert first.state["network_state"] == "NETWORK_DISABLED"
    assert first.state["plan39_reachable"] is False
    assert first.state["authority_issued_or_consumed"] is False
    assert first.state["external_data_bytes_obtained"] == 0


def test_failure_generation_is_0700_0600_no_replace_and_not_success(
    tmp_path: Path,
) -> None:
    generation = derive_preflight_generation(REPO_ROOT)
    published = publish_preflight_generation(
        generation,
        output_base=tmp_path / "preflight",
    )

    assert stat.S_IMODE(os.lstat(published).st_mode) == 0o700
    assert all(
        stat.S_IMODE(os.lstat(path).st_mode) == 0o600
        for path in published.iterdir()
    )
    assert "supplemental-source-plan.json" not in {
        path.name for path in published.iterdir()
    }
    with pytest.raises(FileExistsError):
        publish_preflight_generation(
            generation,
            output_base=tmp_path / "preflight",
        )
    with pytest.raises(PreflightError, match="success"):
        verify_exact_success_under(
            tmp_path / "preflight",
            require_confirmed_coverage=True,
        )


def test_exact_success_discovery_requires_confirmed_replay_flag(
    tmp_path: Path,
) -> None:
    with pytest.raises(PreflightError, match="require-confirmed-coverage"):
        verify_exact_success_under(
            tmp_path,
            require_confirmed_coverage=False,
        )


def test_round_envelope_binds_fresh_non_authorizing_five_identities() -> None:
    generation = derive_preflight_generation(REPO_ROOT)
    payload = generation.round_manifest["payload"]
    identities = payload["round_envelope_identities"]

    assert tuple(identities) == (
        "request_sha256",
        "state_attestation_sha256",
        "target_sha256",
        "binding_sha256",
        "nonce_sha256",
    )
    assert len(set(identities.values())) == 5
    assert all(len(value) == 64 for value in identities.values())
    assert payload["authorizes_provider_execution"] is False
    assert payload["authorizes_import"] is False
    assert payload["authority_inherited"] is False
    assert payload["outcome"] == "INSUFFICIENT_CONFIRMED_COVERAGE"
