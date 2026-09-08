"""Fail-closed acceptance tests for the Phase 2 evidence ledger."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from itda.cli import verify_phase2_evidence as verifier

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PHASE_DIR = REPOSITORY_ROOT / ".planning/phases/02-canonical-36-rights-and-evaluation-manifest"
REQUIREMENTS = REPOSITORY_ROOT / ".planning/REQUIREMENTS.md"
SQLITE_ROOT = REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/sqlite"
SEAL_RECEIPT = SQLITE_ROOT / "real-manifest-seal-receipt.json"
EVIDENCE_INDEX = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/release/phase-02-evidence-index.json"
)
SOURCE_AUDIT = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/release/phase-02-source-audit.json"
)
SOURCE_AUDIT_SUCCESSOR = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/release/phase-02-source-audit-v2.json"
)
SOURCE_AUDIT_CLOSEOUT_SUCCESSOR = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/release/phase-02-source-audit-v3.json"
)
CURRENT_EVIDENCE_INDEX = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/release/phase-02-evidence-index-v2.json"
)
VERIFICATION_MATRIX_V1 = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/release/phase-02-verification-matrix-v1.json"
)
VERIFICATION_MATRIX_V2 = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/release/phase-02-verification-matrix-v2.json"
)
CLOSEOUT_EVIDENCE_INDEX = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/release/phase-02-evidence-index-v3.json"
)
GUARD_ROOT = REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/release/gap-closure-guards"
GRAMMAR_MIGRATION_COMMIT = "81d750e4df7a97207c7f70f948ae02a34f229e56"
LINEAGE_PREDECESSOR = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/lineage/v1-immutability-manifest.json"
)
LINEAGE_SUCCESSOR = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/lineage/v1-immutability-manifest-v2.json"
)
RIGHTS_PROJECTION = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/rights/rights-projection.json"
)
OBJECTIVE_EVIDENCE = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/audit/candidate-objective-evidence.json"
)
RIGHTS_CURRENT_PARENT = (
    REPOSITORY_ROOT
    / "artifacts/restricted/catalog/v2/rights/rights-current-parent-attestation-v1.json"
)
PLAN62_BEFORE = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/release/gap-closure-guards/"
    "02-62-protected-before.json"
)


class CountingClock:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self) -> datetime:
        self.calls += 1
        return datetime(2026, 8, 2, 15, 40, 0, tzinfo=UTC)


def _canonical(payload: object) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run_module(module: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", module, *arguments],
        cwd=REPOSITORY_ROOT / "backend",
        check=False,
        capture_output=True,
        text=True,
    )


def _requirements_preimage_bytes() -> bytes:
    raw = REQUIREMENTS.read_bytes()
    transition = json.loads(EVIDENCE_INDEX.read_bytes())["requirements_transition"]
    if hashlib.sha256(raw).hexdigest() == transition["preimage_sha256"]:
        return raw
    assert hashlib.sha256(raw).hexdigest() == transition["predicted_postimage_sha256"]
    for replacement in reversed(transition["replacement_allowlist"]):
        before = replacement["after"].encode("utf-8")
        after = replacement["before"].encode("utf-8")
        assert raw.count(before) == 1
        raw = raw.replace(before, after, 1)
    assert hashlib.sha256(raw).hexdigest() == transition["preimage_sha256"]
    return raw


@pytest.fixture(scope="module")
def source_evidence_index() -> Path:
    verifier.verify_evidence_index(REPOSITORY_ROOT, EVIDENCE_INDEX)
    return EVIDENCE_INDEX


def test_transition_contract_captures_one_clock_and_exact_three_replacements() -> None:
    clock = CountingClock()
    preimage = _requirements_preimage_bytes()
    transition = verifier.build_requirements_transition(preimage, clock=clock)

    assert clock.calls == 1
    assert transition["acceptance_timestamp"] == "2026-08-02T15:40:00Z"
    assert transition["acceptance_note"] == verifier.ACCEPTANCE_NOTE
    assert transition["changed_requirement_ids"] == ["DATA-08"]
    assert transition["replacement_count"] == 3
    assert len(transition["replacement_allowlist"]) == 3
    assert transition["preimage_sha256"] == hashlib.sha256(preimage).hexdigest()
    postimage = verifier.apply_transition_to_bytes(preimage, transition)
    assert transition["predicted_postimage_sha256"] == hashlib.sha256(postimage).hexdigest()


def test_transition_contract_rejects_wrong_preimage_and_extra_replacement() -> None:
    preimage = _requirements_preimage_bytes()
    transition = verifier.build_requirements_transition(
        preimage,
        clock=lambda: datetime(2026, 8, 2, 15, 40, 0, tzinfo=UTC),
    )
    with pytest.raises(verifier.Phase2EvidenceError):
        verifier.apply_transition_to_bytes(preimage + b"\n", transition)

    hostile = dict(transition)
    hostile["replacement_allowlist"] = [
        *transition["replacement_allowlist"],
        {"before": "Phase 2", "after": "Phase II", "kind": "extra"},
    ]
    with pytest.raises(verifier.Phase2EvidenceError):
        verifier.apply_transition_to_bytes(preimage, hostile)


def test_live_sqlite_receipt_and_history_are_sanitized_and_exact() -> None:
    sqlite = verifier.verify_sqlite_successor(
        REPOSITORY_ROOT,
        receipt_path=SEAL_RECEIPT,
        authority_root=SQLITE_ROOT,
    )
    history = verifier.verify_sqlite_supersession_history(REPOSITORY_ROOT)

    assert sqlite["counts"] == {"development": 24, "held_out": 12, "total": 36}
    assert sqlite["integrity_check"] == "ok"
    assert sqlite["foreign_key_check_count"] == 0
    assert sqlite["sidecars_absent"] is True
    assert len(history["history_records"]) == 4
    assert len(history["reachable_partial_commits"]) == 3
    serialized = _canonical({"sqlite": sqlite, "history": history}).decode("utf-8").casefold()
    for fragment in verifier.FORBIDDEN_OUTPUT_FRAGMENTS:
        assert fragment not in serialized


def test_supersession_copy_rejects_history_pointer_and_summary_faults(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "phase"
    fixture.mkdir()
    for plan_id in verifier.POSTGRESQL_HISTORY:
        for suffix in ("POSTGRESQL-HISTORY.md", "SUPERSEDED.md"):
            shutil.copyfile(
                PHASE_DIR / f"02-{plan_id}-{suffix}",
                fixture / f"02-{plan_id}-{suffix}",
            )
    verifier.verify_sqlite_supersession_history(
        REPOSITORY_ROOT,
        phase_dir=fixture,
        verify_discovery=False,
        verify_commits=False,
    )

    history = fixture / "02-29-POSTGRESQL-HISTORY.md"
    history.write_bytes(history.read_bytes() + b"\n")
    with pytest.raises(verifier.Phase2EvidenceError):
        verifier.verify_sqlite_supersession_history(
            REPOSITORY_ROOT,
            phase_dir=fixture,
            verify_discovery=False,
            verify_commits=False,
        )

    shutil.copyfile(PHASE_DIR / history.name, history)
    (fixture / "02-30-SUMMARY.md").write_text("fabricated\n", encoding="utf-8")
    with pytest.raises(verifier.Phase2EvidenceError):
        verifier.verify_sqlite_supersession_history(
            REPOSITORY_ROOT,
            phase_dir=fixture,
            verify_discovery=False,
            verify_commits=False,
        )


def test_summary_owner_rejects_missing_or_tampered_successor(tmp_path: Path) -> None:
    summary = PHASE_DIR / "02-59-SUMMARY.md"
    verifier.verify_summary_owner(summary, "59")

    hostile = tmp_path / summary.name
    hostile.write_bytes(summary.read_bytes().replace(b"status: complete", b"status: pending"))
    with pytest.raises(verifier.Phase2EvidenceError):
        verifier.verify_summary_owner(hostile, "59")
    with pytest.raises(verifier.Phase2EvidenceError):
        verifier.verify_summary_owner(tmp_path / "missing.md", "59")


def test_build_and_verify_evidence_index_is_no_replace_and_membership_free(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "phase-02-evidence-index.json"
    requirements = tmp_path / "REQUIREMENTS.md"
    requirements.write_bytes(_requirements_preimage_bytes())
    monkeypatch.setattr(verifier, "REQUIREMENTS_RELATIVE", requirements)
    clock = CountingClock()
    built = verifier.build_evidence_index(
        REPOSITORY_ROOT,
        output,
        receipt_path=SEAL_RECEIPT,
        authority_root=SQLITE_ROOT,
        clock=clock,
    )
    assert clock.calls == 1
    verified = verifier.verify_evidence_index(REPOSITORY_ROOT, output)
    assert verified == built
    assert output.read_bytes() == _canonical(built)
    assert built["status"] == "PASS"
    assert built["requirements_transition"]["replacement_count"] == 3
    assert not any(
        fragment in output.read_text(encoding="utf-8").casefold()
        for fragment in verifier.FORBIDDEN_OUTPUT_FRAGMENTS
    )

    with pytest.raises(FileExistsError):
        verifier.build_evidence_index(
            REPOSITORY_ROOT,
            output,
            receipt_path=SEAL_RECEIPT,
            authority_root=SQLITE_ROOT,
            clock=clock,
        )


def test_evidence_index_rejects_transition_or_owner_tampering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "phase-02-evidence-index.json"
    requirements = tmp_path / "REQUIREMENTS.md"
    requirements.write_bytes(_requirements_preimage_bytes())
    monkeypatch.setattr(verifier, "REQUIREMENTS_RELATIVE", requirements)
    payload = verifier.build_evidence_index(
        REPOSITORY_ROOT,
        output,
        receipt_path=SEAL_RECEIPT,
        authority_root=SQLITE_ROOT,
        clock=lambda: datetime(2026, 8, 2, 15, 40, 0, tzinfo=UTC),
    )
    payload["requirements_transition"]["replacement_count"] = 4
    output.write_bytes(_canonical(payload))
    with pytest.raises(verifier.Phase2EvidenceError):
        verifier.verify_evidence_index(REPOSITORY_ROOT, output)


def test_no_active_postgresql_acceptance_claims_are_registered() -> None:
    active = " ".join(verifier.ACTIVE_OWNER_NAMES).casefold()
    for forbidden in (
        "named-connection",
        "exact-0003",
        "advisory-lock",
        "sqlstate",
        "security definer",
        "effective-role",
    ):
        assert forbidden not in active


def test_source_audit_covers_all_four_sources_and_is_deterministic(
    tmp_path: Path, source_evidence_index: Path
) -> None:
    audit_path = tmp_path / "phase-02-source-audit.json"
    built = verifier.build_source_audit(REPOSITORY_ROOT, audit_path, source_evidence_index)
    verified = verifier.verify_source_audit(REPOSITORY_ROOT, audit_path, source_evidence_index)

    assert verified == built
    assert built["status"] == "PASS"
    assert built["status_counts"]["MISSING"] == 0
    assert set(built["source_counts"]) == {"CONTEXT", "GOAL", "REQ", "RESEARCH"}
    rows = built["rows"]
    identifiers = {(row["source"], row["id"]) for row in rows}
    assert {("REQ", f"DATA-{ordinal:02d}") for ordinal in range(1, 9)} <= identifiers
    assert {("CONTEXT", f"D-{ordinal:02d}") for ordinal in range(1, 35)} <= identifiers
    assert {("CONTEXT", f"REINF-{ordinal:02d}") for ordinal in range(1, 19)} <= identifiers


def test_published_source_audit_survives_normal_roadmap_closeout() -> None:
    with pytest.raises(verifier.Phase2EvidenceError, match="terminal owner universe"):
        verifier.verify_source_audit_closeout_successor(
            REPOSITORY_ROOT,
            SOURCE_AUDIT_CLOSEOUT_SUCCESSOR,
            predecessor_source_audit_successor=SOURCE_AUDIT_SUCCESSOR,
            predecessor_current_evidence_index=CURRENT_EVIDENCE_INDEX,
        )
    verified = json.loads(SOURCE_AUDIT_CLOSEOUT_SUCCESSOR.read_bytes())
    verifier._validate_closeout_source_audit_payload(verified)
    assert verified["status"] == "PASS"
    assert verified["status_counts"]["MISSING"] == 0
    assert verified["source_counts"] == {
        "CONTEXT": 56,
        "GOAL": 1,
        "REQ": 8,
        "RESEARCH": 11,
    }


def test_source_audit_successor_rejects_broad_or_unowned_grammar_migration(
    tmp_path: Path,
) -> None:
    with pytest.raises(verifier.Phase2EvidenceError):
        verifier.build_source_audit_successor(
            REPOSITORY_ROOT,
            tmp_path / "broad.json",
            predecessor_source_audit=SOURCE_AUDIT,
            predecessor_evidence_index=EVIDENCE_INDEX,
            grammar_migration_commit="81d750e^",
        )

    with pytest.raises(verifier.Phase2EvidenceError):
        verifier.build_source_audit_successor(
            REPOSITORY_ROOT,
            tmp_path / "unowned.json",
            predecessor_source_audit=SOURCE_AUDIT,
            predecessor_evidence_index=EVIDENCE_INDEX,
            grammar_migration_commit="HEAD",
        )


def test_historical_source_audit_predecessor_remains_strict() -> None:
    before = SOURCE_AUDIT.read_bytes()
    with pytest.raises(
        verifier.Phase2EvidenceError,
        match="source audit differs from exact live recomputation",
    ):
        verifier.verify_source_audit(REPOSITORY_ROOT, SOURCE_AUDIT, EVIDENCE_INDEX)
    assert SOURCE_AUDIT.read_bytes() == before


def test_closeout_successor_classifies_exact_plan62_delta() -> None:
    predecessor = json.loads(SOURCE_AUDIT_SUCCESSOR.read_bytes())
    payload = verifier._derive_closeout_source_audit_payload(
        predecessor,
        roadmap_text=(REPOSITORY_ROOT / ".planning/ROADMAP.md").read_text(encoding="utf-8"),
        requirements_text=REQUIREMENTS.read_text(encoding="utf-8"),
        closeout=verifier._verify_plan62_closeout(REPOSITORY_ROOT),
    )

    assert payload["status_counts"] == {"COVERED": 72, "EXCLUDED": 4, "MISSING": 0}
    assert len(payload["rows"]) == 76
    migration = payload["closeout_migration"]
    assert migration["row_count"] == 51
    assert migration["added_plan_owner"] == "02-62"
    assert migration["changed_fields"] == ["plan_owners"]


def test_closeout_successor_is_identical_across_plan63_summary_and_roadmap_closeout() -> None:
    predecessor = json.loads(SOURCE_AUDIT_SUCCESSOR.read_bytes())
    roadmap = (REPOSITORY_ROOT / ".planning/ROADMAP.md").read_text(encoding="utf-8")
    closed = roadmap.replace(
        "**Plans**: 47/48 plans complete (1 verification closeout-stability plan pending)",
        "**Plans**: 48/48 plans complete",
    ).replace(
        "- [ ] 02-63-PLAN.md — terminal-owner closeout-stable Phase 2 audit and current evidence",
        "- [x] 02-63-PLAN.md — terminal-owner closeout-stable Phase 2 audit and current evidence",
    )
    closeout = verifier._verify_plan62_closeout(REPOSITORY_ROOT)
    before = verifier._derive_closeout_source_audit_payload(
        predecessor,
        roadmap_text=roadmap,
        requirements_text=REQUIREMENTS.read_text(encoding="utf-8"),
        closeout=closeout,
    )
    after = verifier._derive_closeout_source_audit_payload(
        predecessor,
        roadmap_text=closed,
        requirements_text=REQUIREMENTS.read_text(encoding="utf-8"),
        closeout=closeout,
    )
    assert verifier.canonical_json_bytes(before) == verifier.canonical_json_bytes(after)


def test_closeout_successor_contains_no_plan63_semantic_owner_before_or_after_closeout() -> None:
    payload = verifier._derive_closeout_source_audit_payload(
        json.loads(SOURCE_AUDIT_SUCCESSOR.read_bytes()),
        roadmap_text=(REPOSITORY_ROOT / ".planning/ROADMAP.md").read_text(encoding="utf-8"),
        requirements_text=REQUIREMENTS.read_text(encoding="utf-8"),
        closeout=verifier._verify_plan62_closeout(REPOSITORY_ROOT),
    )
    assert all("02-63" not in row["plan_owners"] for row in payload["rows"])
    verifier._validate_closeout_source_audit_payload(payload)


def test_closeout_successor_rejects_recursive_or_out_of_universe_owner() -> None:
    payload = verifier._derive_closeout_source_audit_payload(
        json.loads(SOURCE_AUDIT_SUCCESSOR.read_bytes()),
        roadmap_text=(REPOSITORY_ROOT / ".planning/ROADMAP.md").read_text(encoding="utf-8"),
        requirements_text=REQUIREMENTS.read_text(encoding="utf-8"),
        closeout=verifier._verify_plan62_closeout(REPOSITORY_ROOT),
    )
    payload["rows"][0]["plan_owners"].append("02-63")
    payload["source_audit_closeout_successor_sha256"] = verifier._self_hash(
        payload, "source_audit_closeout_successor_sha256"
    )
    with pytest.raises(verifier.Phase2EvidenceError, match="semantic owner"):
        verifier._validate_closeout_source_audit_payload(payload)

    with pytest.raises(verifier.Phase2EvidenceError, match="terminal owner universe"):
        verifier._validate_terminal_phase_inventory(
            REPOSITORY_ROOT,
            executable_plan_ids=(*verifier.TERMINAL_SEMANTIC_OWNER_IDS, "02-63", "02-64"),
            summary_plan_ids=(*verifier.TERMINAL_SEMANTIC_OWNER_IDS, "02-64"),
        )


def test_closeout_successor_rejects_semantic_source_or_predecessor_drift() -> None:
    roadmap = (REPOSITORY_ROOT / ".planning/ROADMAP.md").read_text(encoding="utf-8")
    with pytest.raises(verifier.Phase2EvidenceError, match="Phase 2 goal"):
        verifier._roadmap_phase2_semantic_commitment(
            roadmap.replace("legally usable", "legally ambiguous", 1)
        )
    with pytest.raises(verifier.Phase2EvidenceError, match="DATA-08"):
        verifier._requirements_phase2_semantic_commitment(
            REQUIREMENTS.read_text(encoding="utf-8").replace(
                "24개 DEV와 12개 BLIND", "23개 DEV와 13개 BLIND", 1
            )
        )

    predecessor = json.loads(SOURCE_AUDIT_SUCCESSOR.read_bytes())
    predecessor["rows"][0]["status"] = "MISSING"
    with pytest.raises(verifier.Phase2EvidenceError, match="predecessor"):
        verifier._derive_closeout_source_audit_payload(
            predecessor,
            roadmap_text=roadmap,
            requirements_text=REQUIREMENTS.read_text(encoding="utf-8"),
            closeout=verifier._verify_plan62_closeout(REPOSITORY_ROOT),
        )


def test_closeout_matrix_v2_migrates_only_two_commands_and_adds_hostile_suite() -> None:
    registry = verifier._matrix_command_registry_v2(
        REPOSITORY_ROOT,
        source_audit_closeout_successor=SOURCE_AUDIT_CLOSEOUT_SUCCESSOR,
    )
    command_ids = [command_id for commands in registry.values() for command_id, _, _ in commands]
    assert len(command_ids) == 29
    assert command_ids.count("C-tests-hostile-closeout-stability") == 1
    migration = verifier._matrix_v2_migration(
        REPOSITORY_ROOT,
        registry,
        predecessor_matrix=VERIFICATION_MATRIX_V1,
    )
    assert migration["changed_command_ids"] == [
        "H-source-audit-successor",
        "H-current-evidence-inputs",
    ]
    assert migration["added_command_ids"] == ["C-tests-hostile-closeout-stability"]


@pytest.mark.parametrize("fault", ["command_id", "argv_sha256", "shard_id", "row_order"])
def test_matrix_v2_receipt_rejects_rehashed_row_identity_hash_shard_and_order_drift(
    tmp_path: Path, fault: str
) -> None:
    hostile = json.loads(VERIFICATION_MATRIX_V2.read_bytes())
    commands = hostile["commands"]
    if fault == "row_order":
        commands[0], commands[1] = commands[1], commands[0]
    elif fault == "shard_id":
        commands[0]["shard_id"] = "H"
    elif fault == "command_id":
        commands[0]["command_id"] = f"{commands[0]['command_id']}-forged"
    else:
        commands[0]["argv_sha256"] = "0" * 64
    hostile["verification_matrix_sha256"] = verifier._self_hash(
        hostile, "verification_matrix_sha256"
    )
    hostile_path = tmp_path / f"hostile-{fault}.json"
    hostile_path.write_bytes(_canonical(hostile))

    with pytest.raises(verifier.Phase2EvidenceError, match="command rows"):
        verifier.verify_final_verification_matrix_v2_receipt(
            REPOSITORY_ROOT,
            hostile_path,
            source_audit_closeout_successor=SOURCE_AUDIT_CLOSEOUT_SUCCESSOR,
            predecessor_verification_matrix=VERIFICATION_MATRIX_V1,
        )


def test_matrix_v2_current_real_rows_equal_closed_registry() -> None:
    registry = verifier._matrix_command_registry_v2(
        REPOSITORY_ROOT,
        source_audit_closeout_successor=SOURCE_AUDIT_CLOSEOUT_SUCCESSOR,
    )
    expected = verifier._matrix_spec(registry)
    recorded = json.loads(VERIFICATION_MATRIX_V2.read_bytes())
    actual = [
        {
            "shard_id": row["shard_id"],
            "command_id": row["command_id"],
            "argv_sha256": row["argv_sha256"],
        }
        for row in recorded["commands"]
    ]

    assert len(actual) == 29
    assert actual == expected
    assert (
        verifier.verify_final_verification_matrix_v2_receipt(
            REPOSITORY_ROOT,
            VERIFICATION_MATRIX_V2,
            source_audit_closeout_successor=SOURCE_AUDIT_CLOSEOUT_SUCCESSOR,
            predecessor_verification_matrix=VERIFICATION_MATRIX_V1,
        )["status"]
        == "PASS"
    )


def test_plan64_successor_survives_summary_and_roadmap_closeout() -> None:
    plans = (*verifier.TERMINAL_SEMANTIC_OWNER_IDS, "02-63", "02-64")
    before_summaries = (*verifier.TERMINAL_SEMANTIC_OWNER_IDS, "02-63")
    roadmap = (REPOSITORY_ROOT / ".planning/ROADMAP.md").read_text(encoding="utf-8")
    open_plan64 = (
        "- [ ] 02-64-PLAN.md — exact ordered matrix receipt-row binding and "
        "versioned post-closeout acceptance"
    )
    closed_plan64 = (
        "- [x] 02-64-PLAN.md — exact ordered matrix receipt-row binding and "
        "versioned post-closeout acceptance"
    )
    open_count = "**Plans**: 48/49 plans complete (1 matrix receipt-row binding gap plan pending)"
    closed_count = "**Plans**: 49/49 plans complete"
    if closed_count in roadmap:
        opened = roadmap.replace(closed_count, open_count, 1).replace(closed_plan64, open_plan64, 1)
        closed = roadmap
    else:
        opened = roadmap
        closed = roadmap.replace(open_count, closed_count, 1).replace(open_plan64, closed_plan64, 1)
    assert opened != closed
    before = verifier._plan64_successor_lifecycle_projection(
        REPOSITORY_ROOT,
        roadmap_text=opened,
        requirements_text=REQUIREMENTS.read_text(encoding="utf-8"),
        executable_plan_ids=plans,
        summary_plan_ids=before_summaries,
    )
    after = verifier._plan64_successor_lifecycle_projection(
        REPOSITORY_ROOT,
        roadmap_text=closed,
        requirements_text=REQUIREMENTS.read_text(encoding="utf-8"),
        executable_plan_ids=plans,
        summary_plan_ids=(*before_summaries, "02-64"),
        plan64_summary_text='---\nplan: "64"\nstatus: complete\n---\n# Summary\n',
    )

    assert verifier.canonical_json_bytes(before) == verifier.canonical_json_bytes(after)
    assert before["inventory"]["producer_plan_ids"] == ["02-63", "02-64"]
    assert before["inventory"]["semantic_owner_ids"] == list(verifier.TERMINAL_SEMANTIC_OWNER_IDS)


def test_plan64_successor_rejects_recursive_later_and_protected_guard_drift(
    tmp_path: Path,
) -> None:
    plans = (*verifier.TERMINAL_SEMANTIC_OWNER_IDS, "02-63", "02-64")
    summaries = (*verifier.TERMINAL_SEMANTIC_OWNER_IDS, "02-63")
    with pytest.raises(verifier.Phase2EvidenceError, match="executable plan intrusion"):
        verifier._validate_plan64_phase_inventory(
            REPOSITORY_ROOT,
            executable_plan_ids=(*plans, "02-65"),
            summary_plan_ids=summaries,
        )

    source = json.loads(SOURCE_AUDIT_CLOSEOUT_SUCCESSOR.read_bytes())
    source["rows"][0]["plan_owners"].append("02-64")
    source["source_audit_closeout_successor_sha256"] = verifier._self_hash(
        source, "source_audit_closeout_successor_sha256"
    )
    with pytest.raises(verifier.Phase2EvidenceError, match="semantic owner"):
        verifier._validate_closeout_source_audit_payload(source)

    before = json.loads((GUARD_ROOT / "02-64-protected-before.json").read_bytes())
    after = json.loads(json.dumps(before))
    after["stage"] = "after"
    after["owners"][0]["sha256"] = "0" * 64
    after["identity_rows_sha256"] = verifier._sha256_bytes(
        verifier.canonical_json_bytes(after["owners"])
    )
    after["protected_set_sha256"] = verifier._sha256_bytes(
        verifier.canonical_json_bytes(
            {"owners": after["owners"], "required_absences": after["required_absences"]}
        )
    )
    after["protected_manifest_sha256"] = verifier._self_hash(after, "protected_manifest_sha256")
    before_path = tmp_path / "02-64-protected-before.json"
    after_path = tmp_path / "02-64-protected-after.json"
    before_path.write_bytes(_canonical(before))
    after_path.write_bytes(_canonical(after))
    with pytest.raises(verifier.Phase2EvidenceError, match="not exact equal"):
        verifier.compare_protected_manifest_paths(before_path, after_path, require_exact=True)


def test_closeout_evidence_index_rejects_stale_parent_or_guard() -> None:
    predecessor = json.loads(CURRENT_EVIDENCE_INDEX.read_bytes())
    with pytest.raises(verifier.Phase2EvidenceError):
        verifier._validate_closeout_evidence_payload({}, require_after_guard=False)

    predecessor["current_evidence_index_sha256"] = "0" * 64
    with pytest.raises(verifier.Phase2EvidenceError, match="predecessor"):
        verifier._validate_current_evidence_predecessor(predecessor)

    before = json.loads((GUARD_ROOT / "02-63-protected-before.json").read_bytes())
    before["protected_set_sha256"] = "0" * 64
    with pytest.raises(verifier.Phase2EvidenceError):
        verifier._validate_plan63_protected_manifest(REPOSITORY_ROOT, before, stage="before")


def test_closeout_phase2_acceptance_requires_four_exact_guard_pairs() -> None:
    transition = json.loads(CURRENT_EVIDENCE_INDEX.read_bytes())["requirements_transition"]
    hostile = {
        "schema_version": verifier.CLOSEOUT_EVIDENCE_SCHEMA_VERSION,
        "status": "PASS",
        "owner_names": list(verifier.CLOSEOUT_OWNER_NAMES),
        "requirements_transition": transition,
        "guard_evidence": [{"comparison_status": "EXACT_EQUAL"}] * 3,
        "closeout_evidence_index_sha256": "",
    }
    hostile["closeout_evidence_index_sha256"] = verifier._self_hash(
        hostile, "closeout_evidence_index_sha256"
    )
    with pytest.raises(verifier.Phase2EvidenceError, match="guard"):
        verifier._validate_closeout_evidence_payload(hostile, require_after_guard=True)


def test_closeout_composition_is_membership_free_and_requirements_immutable() -> None:
    requirements_before = REQUIREMENTS.read_bytes()
    with pytest.raises(verifier.Phase2EvidenceError):
        verifier._assert_closeout_privacy({"status": "PASS", "ordered_place_ids": ["forbidden"]})
    assert REQUIREMENTS.read_bytes() == requirements_before

    transition = json.loads(CURRENT_EVIDENCE_INDEX.read_bytes())["requirements_transition"]
    assert transition["changed_requirement_ids"] == ["DATA-08"]
    assert transition["replacement_count"] == 3
    assert transition["acceptance_timestamp"] == "2026-08-02T15:54:57Z"
    assert transition["acceptance_note"] == verifier.ACCEPTANCE_NOTE


def test_current_checkout_requires_v1_lineage_successor() -> None:
    protected_before = PLAN62_BEFORE.read_bytes()
    historical = _run_module(
        "itda.cli.fingerprint_catalog_v1",
        "--verify",
        str(LINEAGE_PREDECESSOR),
    )
    assert historical.returncode == 1
    assert "FingerprintError" in historical.stderr
    current = _run_module(
        "itda.cli.fingerprint_catalog_v1",
        "--verify-successor",
        str(LINEAGE_SUCCESSOR),
        "--predecessor",
        str(LINEAGE_PREDECESSOR),
    )
    assert current.returncode == 0, current.stderr
    assert PLAN62_BEFORE.read_bytes() == protected_before


def test_current_checkout_requires_rights_current_parent_attestation() -> None:
    protected_before = PLAN62_BEFORE.read_bytes()
    historical = _run_module(
        "itda.cli.project_catalog_rights_v2",
        "--check-bundle",
        str(RIGHTS_PROJECTION),
        str(OBJECTIVE_EVIDENCE),
    )
    assert historical.returncode == 1
    assert "FingerprintError" in historical.stderr
    current = _run_module(
        "itda.cli.project_catalog_rights_v2",
        "--check-current-bundle",
        str(RIGHTS_CURRENT_PARENT),
        "--lineage-successor",
        str(LINEAGE_SUCCESSOR),
        "--rights",
        str(RIGHTS_PROJECTION),
        "--objective-evidence",
        str(OBJECTIVE_EVIDENCE),
    )
    assert current.returncode == 0, current.stderr
    assert PLAN62_BEFORE.read_bytes() == protected_before


def test_current_checkout_requires_source_audit_successor() -> None:
    protected_before = PLAN62_BEFORE.read_bytes()
    historical = _run_module(
        "itda.cli.verify_phase2_evidence",
        "--verify-source-audit",
        str(SOURCE_AUDIT),
        "--evidence-index",
        str(EVIDENCE_INDEX),
    )
    assert historical.returncode == 1
    assert "Phase2EvidenceError" in historical.stderr
    pre_closeout = _run_module(
        "itda.cli.verify_phase2_evidence",
        "--verify-source-audit-successor",
        str(SOURCE_AUDIT_SUCCESSOR),
        "--predecessor-source-audit",
        str(SOURCE_AUDIT),
        "--predecessor-evidence-index",
        str(EVIDENCE_INDEX),
    )
    assert pre_closeout.returncode == 1
    assert "Phase2EvidenceError" in pre_closeout.stderr
    current = _run_module(
        "itda.cli.verify_phase2_evidence",
        "--verify-source-audit-closeout-successor",
        str(SOURCE_AUDIT_CLOSEOUT_SUCCESSOR),
        "--predecessor-source-audit-successor",
        str(SOURCE_AUDIT_SUCCESSOR),
        "--predecessor-current-evidence-index",
        str(CURRENT_EVIDENCE_INDEX),
    )
    assert current.returncode == 1
    assert "terminal owner universe" in current.stderr
    recorded = json.loads(SOURCE_AUDIT_CLOSEOUT_SUCCESSOR.read_bytes())
    verifier._validate_closeout_source_audit_payload(recorded)
    assert recorded["status"] == "PASS"
    assert PLAN62_BEFORE.read_bytes() == protected_before


def test_current_evidence_index_rejects_missing_owner_or_matrix_shard(
    tmp_path: Path,
) -> None:
    assert verifier._resolve_owner_input(REPOSITORY_ROOT, SOURCE_AUDIT_SUCCESSOR) == (
        SOURCE_AUDIT_SUCCESSOR.resolve()
    )
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    with pytest.raises(verifier.Phase2EvidenceError, match="escapes"):
        verifier._resolve_owner_input(REPOSITORY_ROOT, outside)
    with pytest.raises(verifier.Phase2EvidenceError):
        verifier.validate_current_evidence_payload({}, require_after_guard=False)


def test_current_phase2_acceptance_requires_exact_guards_and_original_data08() -> None:
    from itda.cli import build_catalog_contest_profile as contest_profile

    completed_summary = Path(
        ".planning/phases/02-canonical-36-rights-and-evaluation-manifest/02-55-SUMMARY.md"
    )
    assert completed_summary == contest_profile.SUMMARY_REL
    assert (REPOSITORY_ROOT / completed_summary).is_file()
    contest_result = contest_profile.replay_contest_profile(REPOSITORY_ROOT)
    with pytest.raises(
        contest_profile.ContestProfileUncertainError,
        match="Summary must be pending",
    ):
        contest_profile.receipt_for_result(
            contest_result,
            repository_root=REPOSITORY_ROOT,
            disposition="CHECK_ONLY",
        )

    with pytest.raises(verifier.Phase2EvidenceError):
        verifier.validate_current_evidence_payload(
            {
                "schema_version": "itda.phase-02-current-evidence-index.v2",
                "status": "PASS",
                "requirements_transition": {"replacement_count": 4},
            },
            require_after_guard=True,
        )


def test_source_audit_rejects_substituted_closeout_snapshot(tmp_path: Path) -> None:
    hostile_path = tmp_path / "hostile-source-audit.json"
    hostile = json.loads(SOURCE_AUDIT.read_bytes())
    hostile["source_hashes"]["goal"] = "0" * 64
    hostile["source_audit_sha256"] = verifier._self_hash(hostile, "source_audit_sha256")
    hostile_path.write_bytes(_canonical(hostile))
    with pytest.raises(verifier.Phase2EvidenceError):
        verifier.verify_source_audit(REPOSITORY_ROOT, hostile_path, EVIDENCE_INDEX)


@pytest.mark.parametrize("fault", ["missing", "duplicate", "deferred-required"])
def test_source_audit_rejects_missing_duplicate_or_deferred_leakage(
    tmp_path: Path, fault: str, source_evidence_index: Path
) -> None:
    audit_path = tmp_path / "phase-02-source-audit.json"
    payload = verifier.build_source_audit(REPOSITORY_ROOT, audit_path, source_evidence_index)
    rows = payload["rows"]
    if fault == "missing":
        rows.pop()
    elif fault == "duplicate":
        rows.append(dict(rows[0]))
    else:
        excluded = next(row for row in rows if row["status"] == "EXCLUDED")
        excluded["status"] = "COVERED"
    audit_path.write_bytes(_canonical(payload))

    with pytest.raises(verifier.Phase2EvidenceError):
        verifier.verify_source_audit(REPOSITORY_ROOT, audit_path, source_evidence_index)


@pytest.mark.parametrize("decision_id", ["D-30", "D-31", "D-32", "D-33", "D-34"])
def test_source_audit_rejects_weakened_sqlite_decision_owner(
    tmp_path: Path, decision_id: str, source_evidence_index: Path
) -> None:
    audit_path = tmp_path / "phase-02-source-audit.json"
    payload = verifier.build_source_audit(REPOSITORY_ROOT, audit_path, source_evidence_index)
    row = next(
        row for row in payload["rows"] if row["source"] == "CONTEXT" and row["id"] == decision_id
    )
    row["evidence_owners"] = row["evidence_owners"][:-1]
    audit_path.write_bytes(_canonical(payload))

    with pytest.raises(verifier.Phase2EvidenceError):
        verifier.verify_source_audit(REPOSITORY_ROOT, audit_path, source_evidence_index)


def test_requirements_acceptance_applies_exact_bound_postimage_without_index_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    requirements = tmp_path / "REQUIREMENTS.md"
    requirements.write_bytes(_requirements_preimage_bytes())
    index_sha_before = _sha256(EVIDENCE_INDEX)
    real_open = verifier.os.open

    def guarded_open(path: str | Path, flags: int, mode: int = 0o777, **kwargs: int | None) -> int:
        if Path(path) == EVIDENCE_INDEX and flags & (verifier.os.O_WRONLY | verifier.os.O_RDWR):
            raise AssertionError("evidence index write attempted")
        return real_open(path, flags, mode, **kwargs)

    monkeypatch.setattr(verifier.os, "open", guarded_open)
    receipt = verifier.apply_requirements_acceptance(requirements, EVIDENCE_INDEX)
    index = json.loads(EVIDENCE_INDEX.read_bytes())
    transition = index["requirements_transition"]

    assert receipt["replacement_count"] == 3
    assert receipt["changed_requirement_ids"] == ["DATA-08"]
    assert receipt["acceptance_timestamp"] == transition["acceptance_timestamp"]
    assert receipt["acceptance_note"] == transition["acceptance_note"]
    assert _sha256(requirements) == transition["predicted_postimage_sha256"]
    assert _sha256(EVIDENCE_INDEX) == index_sha_before


def test_requirements_acceptance_verifies_reverse_preimage_and_expected_binding(
    tmp_path: Path,
) -> None:
    requirements = tmp_path / "REQUIREMENTS.md"
    requirements.write_bytes(_requirements_preimage_bytes())
    verifier.apply_requirements_acceptance(requirements, EVIDENCE_INDEX)
    transition = json.loads(EVIDENCE_INDEX.read_bytes())["requirements_transition"]
    receipt = verifier.verify_requirements_acceptance(
        requirements,
        EVIDENCE_INDEX,
        expected_timestamp=transition["acceptance_timestamp"],
        expected_note=transition["acceptance_note"],
    )
    assert receipt["recovered_preimage_sha256"] == transition["preimage_sha256"]
    assert receipt["postimage_sha256"] == transition["predicted_postimage_sha256"]

    with pytest.raises(verifier.Phase2EvidenceError):
        verifier.verify_requirements_acceptance(
            requirements,
            EVIDENCE_INDEX,
            expected_timestamp="2026-08-02T15:40:01Z",
            expected_note=transition["acceptance_note"],
        )
    with pytest.raises(verifier.Phase2EvidenceError):
        verifier.verify_requirements_acceptance(
            requirements,
            EVIDENCE_INDEX,
            expected_timestamp=transition["acceptance_timestamp"],
            expected_note="caller-supplied substitute",
        )


def test_requirements_acceptance_rejects_non_data_or_index_transition_tampering(
    tmp_path: Path,
) -> None:
    requirements = tmp_path / "REQUIREMENTS.md"
    requirements.write_bytes(_requirements_preimage_bytes())
    verifier.apply_requirements_acceptance(requirements, EVIDENCE_INDEX)
    requirements.write_bytes(
        requirements.read_bytes().replace(b"# Requirements", b"# Weakened Requirements")
    )
    transition = json.loads(EVIDENCE_INDEX.read_bytes())["requirements_transition"]
    with pytest.raises(verifier.Phase2EvidenceError):
        verifier.verify_requirements_acceptance(
            requirements,
            EVIDENCE_INDEX,
            expected_timestamp=transition["acceptance_timestamp"],
            expected_note=transition["acceptance_note"],
        )

    hostile_index = tmp_path / "hostile-index.json"
    hostile = json.loads(EVIDENCE_INDEX.read_bytes())
    hostile["requirements_transition"]["replacement_count"] = 4
    hostile_index.write_bytes(_canonical(hostile))
    clean_requirements = tmp_path / "clean-requirements.md"
    clean_requirements.write_bytes(_requirements_preimage_bytes())
    with pytest.raises(verifier.Phase2EvidenceError):
        verifier.apply_requirements_acceptance(clean_requirements, hostile_index)
