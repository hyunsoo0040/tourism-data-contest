"""Wave 0 contract for DATA-07 (02-W0-DATA07; D-16 and T-02-05)."""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

CAPABILITY_MODULE = "itda.contracts.catalog_release"
PIPELINE_MODULE = "itda.pipeline.publish_catalog"
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
REVIEW_ROOT = REPOSITORY_ROOT / "artifacts/restricted/catalog/v1/review"


def _capability_or_skip() -> ModuleType:
    if importlib.util.find_spec(CAPABILITY_MODULE) is None:
        pytest.skip("catalog approval production capability is implemented in Plan 02-08")
    return importlib.import_module(CAPABILITY_MODULE)


def _candidate(candidate_number: int, *, eligible: bool = True) -> dict[str, object]:
    return {
        "candidate_id": f"candidate:{candidate_number:03d}",
        "canonical_place_id": f"place:{candidate_number:03d}",
        "name_ko": f"후보 {candidate_number}",
        "coordinates_gate": eligible,
        "description_gate": eligible,
        "operational_gate": eligible,
        "rights_gate": eligible,
        "nonduplicate_gate": eligible,
        "media_gate": eligible,
    }


def _gate_inputs(candidate_count: int = 60, selected_count: int = 36) -> dict[str, object]:
    return {
        "candidates": [_candidate(index) for index in range(1, candidate_count + 1)],
        "ordered_catalog_ids": tuple(
            f"place:{index:03d}" for index in range(1, selected_count + 1)
        ),
        "proposal_seed_dispositions": {
            f"proposal:gyeongju:{index:03d}": "LINKED" for index in range(1, 37)
        },
        "parent_hashes": {
            "collection_report_sha256": "1" * 64,
            "permission_evidence_set_sha256": "2" * 64,
            "crosswalk_revision_sha256": "3" * 64,
            "relationship_revision_sha256": "4" * 64,
            "catalog_audit_sha256": "5" * 64,
        },
        "projection_hashes": {
            "catalog-audit.json": "6" * 64,
            "catalog-audit.parquet": "7" * 64,
            "catalog-audit.csv": "8" * 64,
            "catalog-audit.md": "9" * 64,
        },
    }


def test_catalog_gate_requires_sixty_candidates_all_gates_and_exactly_36() -> None:
    capability = _capability_or_skip()
    report = capability.build_catalog_gate_report(**_gate_inputs())
    assert report.candidate_count >= 60
    assert report.ordered_catalog_count == 36
    assert report.all_required_gates_passed is True
    assert report.unresolved_review_rows == ()
    assert report.catalog_manifest_sha256 == capability.canonical_catalog_sha256(
        report.ordered_catalog_ids
    )


def test_actual_gate_report_preserves_blocked_plan_02_07_truth() -> None:
    pipeline = importlib.import_module(PIPELINE_MODULE)
    report = pipeline.build_catalog_gate_report_from_review_artifacts(
        catalog_audit_path=REVIEW_ROOT / "catalog-audit.json",
        projection_manifest_path=REVIEW_ROOT / "projection-manifest.json",
        crosswalk_review_path=REVIEW_ROOT / "crosswalk-review.json",
        relationship_review_path=REVIEW_ROOT / "relationship-review.json",
    )

    assert report.status == "BLOCKED"
    assert report.candidate_count == 1_592
    assert report.seed_disposition_count == 36
    assert report.selection_eligible_count == 0
    assert report.ordered_catalog_ids == ()
    assert report.ordered_catalog_count == 0
    assert report.all_required_gates_passed is False
    assert report.crosswalk_review_required_count == 718
    assert report.relationship_review_required_count == 874
    assert report.rights_disposition_counts == {
        "ALLOWED": 920,
        "BLOCKED_MISSING_PROVENANCE": 663,
        "BLOCKED_EXPLICIT_ASSET_RESTRICTION": 9,
    }
    assert report.seed_disposition_counts == {
        "LINKED": 21,
        "MISSING_WITH_EVIDENCE": 15,
    }
    assert len(report.proposal_seed_dispositions) == 36
    assert (
        sum(disposition == "LINKED" for disposition in report.proposal_seed_dispositions.values())
        == 21
    )
    assert report.representation_check_outcomes == {
        "history_culture": False,
        "history_scenery_boundary": False,
        "image_modern_content": False,
        "rest_walk_immersion": False,
    }
    assert len(report.unresolved_review_rows) == 1_592
    assert {outcome.gate_id for outcome in report.gate_outcomes} == {
        "candidate_pool_minimum",
        "proposal_seed_dispositions",
        "coordinates",
        "meaningful_description",
        "confirmed_operation",
        "rights_eligibility",
        "nonduplicate_poi_unit",
        "media_sufficiency",
        "representation_coverage",
        "human_identity_review",
        "human_relationship_review",
        "exactly_36",
    }
    assert len(report.report_sha256) == 64


def test_actual_gate_report_rejects_projection_manifest_drift(tmp_path: Path) -> None:
    pipeline = importlib.import_module(PIPELINE_MODULE)
    payload = json.loads((REVIEW_ROOT / "projection-manifest.json").read_text())
    payload["canonical_json_sha256"] = "0" * 64
    drifted = tmp_path / "projection-manifest.json"
    drifted.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="projection|canonical"):
        pipeline.build_catalog_gate_report_from_review_artifacts(
            catalog_audit_path=REVIEW_ROOT / "catalog-audit.json",
            projection_manifest_path=drifted,
            crosswalk_review_path=REVIEW_ROOT / "crosswalk-review.json",
            relationship_review_path=REVIEW_ROOT / "relationship-review.json",
        )


@pytest.mark.parametrize(
    ("candidate_count", "selected_count", "match"),
    [(59, 36, "60"), (60, 35, "36"), (60, 37, "36")],
    ids=["under-minimum-candidates", "35-members", "37-members"],
)
def test_catalog_cardinality_failures_are_closed(
    candidate_count: int,
    selected_count: int,
    match: str,
) -> None:
    capability = _capability_or_skip()
    with pytest.raises(ValueError, match=match):
        capability.build_catalog_gate_report(
            **_gate_inputs(
                candidate_count=candidate_count,
                selected_count=selected_count,
            )
        )


def test_failed_gate_or_missing_seed_disposition_blocks_approval() -> None:
    capability = _capability_or_skip()
    failed_gate = _gate_inputs()
    failed_gate["candidates"][0]["rights_gate"] = False
    with pytest.raises(ValueError, match="rights"):
        capability.build_catalog_gate_report(**failed_gate)

    missing_seed = _gate_inputs()
    missing_seed["proposal_seed_dispositions"].pop("proposal:gyeongju:036")
    with pytest.raises(ValueError, match="seed"):
        capability.build_catalog_gate_report(**missing_seed)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("confirm_catalog_sha256", "a" * 63),
        ("confirm_catalog_sha256", "f" * 64),
        ("confirm_adjudication_sha256", "b" * 12),
        ("confirm_adjudication_sha256", "e" * 64),
    ],
    ids=["short-catalog", "stale-catalog", "short-adjudication", "stale-adjudication"],
)
def test_approval_requires_current_full_catalog_and_adjudication_digests(
    field: str,
    value: str,
) -> None:
    capability = _capability_or_skip()
    report = capability.build_catalog_gate_report(**_gate_inputs())
    kwargs = {
        "gate_report": report,
        "catalog_adjudication_sha256": "b" * 64,
        "confirm_catalog_sha256": report.catalog_manifest_sha256,
        "confirm_adjudication_sha256": "b" * 64,
        "reviewer_id": "catalog-reviewer",
        "approved_at": "2026-07-27T05:00:00Z",
    }
    kwargs[field] = value
    with pytest.raises(ValueError, match="64|digest|sha256"):
        capability.approve_catalog(**kwargs)


def test_approval_binds_canonical_json_and_every_linked_projection_hash() -> None:
    capability = _capability_or_skip()
    report = capability.build_catalog_gate_report(**_gate_inputs())
    approval = capability.approve_catalog(
        gate_report=report,
        catalog_adjudication_sha256="b" * 64,
        confirm_catalog_sha256=report.catalog_manifest_sha256,
        confirm_adjudication_sha256="b" * 64,
        reviewer_id="catalog-reviewer",
        approved_at="2026-07-27T05:00:00Z",
    )
    assert approval.catalog_manifest_sha256 == report.catalog_manifest_sha256
    assert approval.catalog_adjudication_sha256 == "b" * 64
    assert approval.projection_hashes == report.projection_hashes
    assert len(approval.catalog_approval_sha256) == 64

    with pytest.raises(ValueError, match="canonical.*JSON"):
        capability.load_catalog_review_truth(Path("catalog-audit.csv"))
    with pytest.raises(ValueError, match="canonical.*JSON"):
        capability.load_catalog_review_truth(Path("catalog-audit.md"))


def test_catalog_publication_is_no_replace(tmp_path: Path) -> None:
    capability = _capability_or_skip()
    report = capability.build_catalog_gate_report(**_gate_inputs())
    approval = capability.approve_catalog(
        gate_report=report,
        catalog_adjudication_sha256="b" * 64,
        confirm_catalog_sha256=report.catalog_manifest_sha256,
        confirm_adjudication_sha256="b" * 64,
        reviewer_id="catalog-reviewer",
        approved_at="2026-07-27T05:00:00Z",
    )
    destination = tmp_path / "approved"
    capability.publish_catalog_release(report, approval, destination)
    first_bytes = {path.name: path.read_bytes() for path in destination.iterdir()}
    with pytest.raises(FileExistsError):
        capability.publish_catalog_release(report, approval, destination)
    assert {path.name: path.read_bytes() for path in destination.iterdir()} == first_bytes


def _review_request_fixture(capability: ModuleType) -> tuple[object, object]:
    gate_inputs = _gate_inputs()
    unresolved = (
        "crosswalk:" + "a" * 64,
        "relationship:" + "b" * 64,
    )
    report = capability.evaluate_catalog_gate_report(
        **gate_inputs,
        unresolved_review_rows=unresolved,
        crosswalk_review_required_count=1,
        relationship_review_required_count=1,
    )
    rows = (
        {
            "row_id": unresolved[0],
            "row_kind": "CROSSWALK",
            "source_proposal_id": "a" * 64,
            "source_revision_sha256": "3" * 64,
            "evidence_refs": ("c" * 64,),
            "parent_hashes": {"collection_report_sha256": "1" * 64},
        },
        {
            "row_id": unresolved[1],
            "row_kind": "RELATIONSHIP",
            "source_proposal_id": "b" * 64,
            "source_revision_sha256": "4" * 64,
            "evidence_refs": ("d" * 64,),
            "parent_hashes": {"relationship_revision_sha256": "4" * 64},
        },
    )
    request = capability.build_catalog_review_request(
        gate_report=report,
        required_rows=rows,
        code_version_hashes={
            "backend/src/itda/contracts/catalog_release.py": hashlib.sha256(
                (REPOSITORY_ROOT / "backend/src/itda/contracts/catalog_release.py").read_bytes()
            ).hexdigest()
        },
        config_version_hashes={
            "backend/pyproject.toml": hashlib.sha256(
                (REPOSITORY_ROOT / "backend/pyproject.toml").read_bytes()
            ).hexdigest()
        },
    )
    return report, request


def _decision_rows(request: object) -> list[dict[str, object]]:
    return [
        {
            "row_id": row.row_id,
            "decision": "ACCEPT",
            "disposition": "REVIEWED_AND_ACCEPTED",
            "reviewer_id": "catalog-reviewer",
            "reviewed_at": "2026-07-27T05:00:00Z",
            "evidence_refs": row.evidence_refs,
            "source_revision_sha256": row.source_revision_sha256,
            "parent_hashes": row.parent_hashes,
        }
        for row in request.required_rows
    ]


def test_actual_review_request_is_hash_bound_and_contains_every_pending_row() -> None:
    pipeline = importlib.import_module(PIPELINE_MODULE)
    gate_report = pipeline.build_catalog_gate_report_from_review_artifacts(
        catalog_audit_path=REVIEW_ROOT / "catalog-audit.json",
        projection_manifest_path=REVIEW_ROOT / "projection-manifest.json",
        crosswalk_review_path=REVIEW_ROOT / "crosswalk-review.json",
        relationship_review_path=REVIEW_ROOT / "relationship-review.json",
    )
    request = pipeline.build_catalog_review_request_from_review_artifacts(
        gate_report=gate_report,
        gate_report_path=REVIEW_ROOT / "catalog-gate-report.json",
        crosswalk_review_path=REVIEW_ROOT / "crosswalk-review.json",
        relationship_review_path=REVIEW_ROOT / "relationship-review.json",
        repository_root=REPOSITORY_ROOT,
    )

    assert request.status == "BLOCKED_AWAITING_ADJUDICATION"
    assert request.ordered_proposed_catalog_ids == ()
    assert request.proposed_catalog_sha256 == gate_report.catalog_manifest_sha256
    assert len(request.required_rows) == 1_592
    assert sum(row.row_kind == "CROSSWALK" for row in request.required_rows) == 718
    assert sum(row.row_kind == "RELATIONSHIP" for row in request.required_rows) == 874
    assert len(request.required_adjudication_rows_sha256) == 64
    assert len(request.catalog_review_request_sha256) == 64
    assert request.gate_report_sha256 == gate_report.report_sha256
    assert request.parent_hashes == gate_report.parent_hashes
    assert request.projection_hashes == gate_report.projection_hashes
    assert request.proposal_seed_dispositions == gate_report.proposal_seed_dispositions
    assert request.code_version_hashes
    assert request.config_version_hashes


def test_catalog_materialization_consumes_exact_adjudication_rows(tmp_path: Path) -> None:
    capability = _capability_or_skip()
    report, request = _review_request_fixture(capability)
    decisions = _decision_rows(request)
    adjudication = capability.prepare_catalog_adjudication(
        review_request=request,
        decisions=decisions,
        reviewer_id="catalog-reviewer",
        reviewed_at="2026-07-27T05:00:00Z",
    )
    verified = capability.verify_catalog_adjudication(
        gate_report=report,
        review_request=request,
        adjudication=adjudication,
        confirm_catalog_sha256=report.catalog_manifest_sha256,
        confirm_adjudication_sha256=adjudication.catalog_adjudication_sha256,
        reviewer_id="catalog-reviewer",
        repository_root=REPOSITORY_ROOT,
    )
    destination = tmp_path / "reviewed"
    capability.materialize_reviewed_catalog(verified, destination)
    assert (destination / "catalog-adjudication.json").is_file()
    revision_sha256, adjudication_sha256 = capability.load_reviewed_catalog_revision(
        destination,
        repository_root=REPOSITORY_ROOT,
    )
    assert len(revision_sha256) == 64
    assert adjudication_sha256 == adjudication.catalog_adjudication_sha256

    arbitrary = tmp_path / "arbitrary.json"
    arbitrary.write_text(
        json.dumps({"catalog_adjudication_sha256": "1" * 64}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="reviewed catalog|directory"):
        capability.load_reviewed_catalog_revision(
            arbitrary,
            repository_root=REPOSITORY_ROOT,
        )

    for bad_decisions, match in (
        (decisions[:-1], "missing"),
        (decisions + [decisions[0]], "duplicate"),
        (decisions + [{**decisions[0], "row_id": "crosswalk:" + "9" * 64}], "extra"),
        (
            [{**decisions[0], "evidence_refs": ("0" * 64,)}, decisions[1]],
            "evidence",
        ),
        (
            [{**decisions[0], "source_revision_sha256": "0" * 64}, decisions[1]],
            "source revision",
        ),
    ):
        with pytest.raises(ValueError, match=match):
            capability.prepare_catalog_adjudication(
                review_request=request,
                decisions=bad_decisions,
                reviewer_id="catalog-reviewer",
                reviewed_at="2026-07-27T05:00:00Z",
            )

    for forbidden in ("02-09-SUMMARY.md", "chat.txt", "decisions.csv"):
        with pytest.raises(ValueError, match="canonical.*JSON"):
            capability.load_adjudication_decisions(Path(forbidden))


def test_verification_rejects_tampered_row_and_stale_code_or_config(
    tmp_path: Path,
) -> None:
    capability = _capability_or_skip()
    report, request = _review_request_fixture(capability)
    adjudication = capability.prepare_catalog_adjudication(
        review_request=request,
        decisions=_decision_rows(request),
        reviewer_id="catalog-reviewer",
        reviewed_at="2026-07-27T05:00:00Z",
    )
    tampered_payload = adjudication.model_dump(mode="json")
    tampered_payload["rows"][0]["evidence_refs"] = ["9" * 64]
    tampered_payload["rows"][0]["row_adjudication_sha256"] = None
    tampered_payload["catalog_adjudication_sha256"] = None
    tampered = capability.CatalogAdjudication.model_validate(tampered_payload)
    with pytest.raises(ValueError, match="evidence|requested row"):
        capability.verify_catalog_adjudication(
            gate_report=report,
            review_request=request,
            adjudication=tampered,
            confirm_catalog_sha256=report.catalog_manifest_sha256,
            confirm_adjudication_sha256=tampered.catalog_adjudication_sha256,
            reviewer_id="catalog-reviewer",
            repository_root=REPOSITORY_ROOT,
        )

    version_root = tmp_path / "version-root"
    for relative in (
        *request.code_version_hashes,
        *request.config_version_hashes,
    ):
        source = REPOSITORY_ROOT / relative
        destination = version_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())
    stale = version_root / next(iter(request.code_version_hashes))
    stale.write_bytes(stale.read_bytes() + b"\n# stale\n")
    with pytest.raises(ValueError, match="code.*hash|version"):
        capability.verify_catalog_adjudication(
            gate_report=report,
            review_request=request,
            adjudication=adjudication,
            confirm_catalog_sha256=report.catalog_manifest_sha256,
            confirm_adjudication_sha256=adjudication.catalog_adjudication_sha256,
            reviewer_id="catalog-reviewer",
            repository_root=version_root,
        )


def test_activation_is_immutable_event(tmp_path: Path) -> None:
    capability = _capability_or_skip()
    events_root = tmp_path / "events"
    first = capability.append_revision_activation_event(
        action="ACTIVATE",
        target_revision_sha256="1" * 64,
        catalog_adjudication_sha256="2" * 64,
        expected_active_revision_sha256=None,
        reviewer_id="catalog-reviewer",
        occurred_at="2026-07-27T05:00:00Z",
        evidence_refs=("3" * 64,),
        events_root=events_root,
        reviewed_revision_sha256s=("1" * 64,),
    )
    first_bytes = tuple(path.read_bytes() for path in events_root.iterdir())
    with pytest.raises(ValueError, match="already active|expected"):
        capability.append_revision_activation_event(
            action="ACTIVATE",
            target_revision_sha256="1" * 64,
            catalog_adjudication_sha256="2" * 64,
            expected_active_revision_sha256=None,
            reviewer_id="catalog-reviewer",
            occurred_at="2026-07-27T05:01:00Z",
            evidence_refs=("3" * 64,),
            events_root=events_root,
            reviewed_revision_sha256s=("1" * 64,),
        )
    assert tuple(path.read_bytes() for path in events_root.iterdir()) == first_bytes
    assert len(first.event_sha256) == 64


def test_rollback_to_prior_reviewed_revision_appends_event(tmp_path: Path) -> None:
    capability = _capability_or_skip()
    events_root = tmp_path / "events"
    first = capability.append_revision_activation_event(
        action="ACTIVATE",
        target_revision_sha256="1" * 64,
        catalog_adjudication_sha256="2" * 64,
        expected_active_revision_sha256=None,
        reviewer_id="catalog-reviewer",
        occurred_at="2026-07-27T05:00:00Z",
        evidence_refs=("3" * 64,),
        events_root=events_root,
        reviewed_revision_sha256s=("1" * 64, "4" * 64),
    )
    second = capability.append_revision_activation_event(
        action="ACTIVATE",
        target_revision_sha256="4" * 64,
        catalog_adjudication_sha256="5" * 64,
        expected_active_revision_sha256="1" * 64,
        reviewer_id="catalog-reviewer",
        occurred_at="2026-07-27T05:01:00Z",
        evidence_refs=("6" * 64,),
        events_root=events_root,
        reviewed_revision_sha256s=("1" * 64, "4" * 64),
    )
    rollback = capability.append_revision_activation_event(
        action="ROLLBACK",
        target_revision_sha256="1" * 64,
        catalog_adjudication_sha256="2" * 64,
        expected_active_revision_sha256="4" * 64,
        reviewer_id="catalog-reviewer",
        occurred_at="2026-07-27T05:02:00Z",
        evidence_refs=("7" * 64,),
        events_root=events_root,
        reviewed_revision_sha256s=("1" * 64, "4" * 64),
    )

    assert len(tuple(events_root.iterdir())) == 3
    assert second.previous_event_sha256 == first.event_sha256
    assert rollback.previous_event_sha256 == second.event_sha256
    assert rollback.previous_active_revision_sha256 == "4" * 64


def test_missing_catalog_approval_is_controlled_red() -> None:
    if importlib.util.find_spec(CAPABILITY_MODULE) is None:
        pytest.fail("PHASE2-MISSING:catalog-approval", pytrace=False)
    importlib.import_module(CAPABILITY_MODULE)
