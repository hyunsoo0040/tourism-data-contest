"""Wave 0 RED contracts for immutable accepted heads and label aggregation."""

from __future__ import annotations

import importlib
import importlib.util
from datetime import UTC, datetime
from types import ModuleType
from typing import Any

import pytest
from pydantic import ValidationError

CAPABILITY_MODULE = "itda.contracts.labeling"
ATTRIBUTE_IDS = ("H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "R1", "R2", "R3", "R4")
SUBMITTED_AT = datetime(2026, 8, 3, tzinfo=UTC)


def _capability() -> ModuleType:
    if importlib.util.find_spec(CAPABILITY_MODULE) is None:
        pytest.fail("PHASE3-MISSING:label-aggregation", pytrace=False)
    return importlib.import_module(CAPABILITY_MODULE)


def _revision(
    capability: ModuleType,
    evaluator: str,
    *,
    h1_score: int | None,
    parent: str | None = None,
    correction_reason: str | None = None,
) -> Any:
    judgments: list[dict[str, object]] = []
    for attribute_id in ATTRIBUTE_IDS:
        score = h1_score if attribute_id == "H1" else 2
        judgments.append(
            {
                "attribute_id": attribute_id,
                "score": score,
                "unknown_reason": "NO_EVIDENCE" if score is None else None,
                "unknown_note": "합성 근거가 없어 판단할 수 없습니다." if score is None else None,
                "evidence": [],
            }
        )
    return capability.RawLabelRevision.model_validate(
        {
            "assignment_id": "synthetic-assignment-alpha",
            "evaluator_pseudonym": evaluator,
            "primary_axis_judgment": "HISTORY_TRADITION",
            "rubric_version": "synthetic-rubric-v1",
            "source_snapshot_version": "synthetic-source-v1",
            "parent_revision_sha256": parent,
            "correction_reason": correction_reason,
            "judgments": judgments,
            "submitted_at": SUBMITTED_AT,
        }
    )


def _accepted(capability: ModuleType, revision: Any, operator: str) -> Any:
    return capability.AcceptedRevisionSelection.model_validate(
        {
            "assignment_id": revision.assignment_id,
            "evaluator_pseudonym": revision.evaluator_pseudonym,
            "accepted_revision_sha256": revision.revision_sha256,
            "operator_pseudonym": operator,
            "selected_at": SUBMITTED_AT,
        }
    )


def test_raw_correction_and_accepted_selection_have_distinct_immutable_hashes() -> None:
    capability = _capability()
    raw = _revision(capability, "synthetic-evaluator-a", h1_score=1)
    raw_bytes = raw.model_dump_json().encode()
    correction = _revision(
        capability,
        "synthetic-evaluator-a",
        h1_score=2,
        parent=raw.revision_sha256,
        correction_reason="합성 근거 재확인",
    )
    accepted = _accepted(capability, correction, "synthetic-operator-a")

    assert correction.parent_revision_sha256 == raw.revision_sha256
    assert len({raw.revision_sha256, correction.revision_sha256, accepted.selection_sha256}) == 3
    revalidated = capability.RawLabelRevision.model_validate_json(raw_bytes)
    assert revalidated.model_dump_json().encode() == raw_bytes


def test_correction_requires_reason_bound_parent_digest() -> None:
    capability = _capability()
    raw = _revision(capability, "synthetic-evaluator-a", h1_score=1)

    with pytest.raises(ValidationError):
        _revision(
            capability,
            "synthetic-evaluator-a",
            h1_score=2,
            parent=raw.revision_sha256,
            correction_reason=None,
        )
    with pytest.raises(ValidationError):
        _revision(
            capability,
            "synthetic-evaluator-a",
            h1_score=2,
            parent=None,
            correction_reason="합성 근거 재확인",
        )


def test_three_submissions_and_two_numeric_scores_are_required() -> None:
    capability = _capability()
    revisions = (
        _revision(capability, "synthetic-evaluator-a", h1_score=1),
        _revision(capability, "synthetic-evaluator-b", h1_score=None),
        _revision(capability, "synthetic-evaluator-c", h1_score=None),
    )
    accepted = tuple(
        _accepted(capability, revision, "synthetic-operator-a") for revision in revisions
    )

    with pytest.raises(capability.LabelExportBlocked, match="at least two numeric scores"):
        capability.aggregate_accepted_revisions(revisions, accepted)
    with pytest.raises(capability.LabelExportBlocked, match="all three evaluator roles"):
        capability.aggregate_accepted_revisions(revisions[:2], accepted[:2])


def test_integer_median_exports_exactly_without_adjudication() -> None:
    capability = _capability()
    revisions = (
        _revision(capability, "synthetic-evaluator-a", h1_score=1),
        _revision(capability, "synthetic-evaluator-b", h1_score=2),
        _revision(capability, "synthetic-evaluator-c", h1_score=3),
    )
    accepted = tuple(
        _accepted(capability, revision, "synthetic-operator-a") for revision in revisions
    )

    export = capability.aggregate_accepted_revisions(revisions, accepted)

    assert export.value_for("H1") == 2
    assert export.aggregation_kind_for("H1") == "EXACT_MEDIAN"
    assert export.adjudication_sha256 is None


def test_half_step_median_requires_explicit_adjudicated_integer() -> None:
    capability = _capability()
    revisions = (
        _revision(capability, "synthetic-evaluator-a", h1_score=1),
        _revision(capability, "synthetic-evaluator-b", h1_score=2),
        _revision(capability, "synthetic-evaluator-c", h1_score=None),
    )
    accepted = tuple(
        _accepted(capability, revision, "synthetic-operator-a") for revision in revisions
    )

    with pytest.raises(capability.AdjudicationRequired) as error:
        capability.aggregate_accepted_revisions(revisions, accepted)
    assert error.value.attribute_id == "H1"
    assert error.value.exact_median == "1.5"

    adjudication = capability.AdjudicatedAttributeValue.model_validate(
        {
            "attribute_id": "H1",
            "exact_median": "1.5",
            "adjudicated_value": 2,
            "reason": "합성 원문을 다시 확인해 정수 값을 선택함",
            "adjudicator_pseudonym": "synthetic-adjudicator-a",
            "adjudicated_at": SUBMITTED_AT,
        }
    )
    export = capability.aggregate_accepted_revisions(
        revisions, accepted, adjudications=(adjudication,)
    )

    assert export.value_for("H1") == 2
    assert export.aggregation_kind_for("H1") == "ADJUDICATED"
    assert (
        len(
            {
                *(revision.revision_sha256 for revision in revisions),
                *(selection.selection_sha256 for selection in accepted),
                adjudication.adjudication_sha256,
                export.export_sha256,
            }
        )
        == 8
    )


def test_revalidation_never_mutates_any_predecessor_bytes() -> None:
    capability = _capability()
    revisions = (
        _revision(capability, "synthetic-evaluator-a", h1_score=1),
        _revision(capability, "synthetic-evaluator-b", h1_score=2),
        _revision(capability, "synthetic-evaluator-c", h1_score=3),
    )
    accepted = tuple(
        _accepted(capability, revision, "synthetic-operator-a") for revision in revisions
    )
    predecessor_bytes = tuple(item.model_dump_json().encode() for item in (*revisions, *accepted))

    first = capability.aggregate_accepted_revisions(revisions, accepted)
    second = capability.AdjudicatedLabelExport.model_validate_json(first.model_dump_json())

    assert first.export_sha256 == second.export_sha256
    assert predecessor_bytes == tuple(
        item.model_dump_json().encode() for item in (*revisions, *accepted)
    )
