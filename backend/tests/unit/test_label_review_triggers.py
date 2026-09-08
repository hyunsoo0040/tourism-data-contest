"""Wave 0 RED truth table for deterministic Phase 3 review triggers."""

from __future__ import annotations

import importlib
import importlib.util
from datetime import UTC, datetime
from types import ModuleType
from typing import Any

import pytest

CAPABILITY_MODULE = "itda.contracts.labeling"
ATTRIBUTE_IDS = ("H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "R1", "R2", "R3", "R4")
SUBMITTED_AT = datetime(2026, 8, 3, tzinfo=UTC)


def _capability() -> ModuleType:
    if importlib.util.find_spec(CAPABILITY_MODULE) is None:
        pytest.fail("PHASE3-MISSING:label-review-triggers", pytrace=False)
    return importlib.import_module(CAPABILITY_MODULE)


def _judgment(attribute_id: str, score: int | None, *, direct: bool = True) -> dict[str, Any]:
    if score is None:
        return {
            "attribute_id": attribute_id,
            "score": None,
            "unknown_reason": "NO_EVIDENCE",
            "unknown_note": "합성 근거가 없어 판단할 수 없습니다.",
            "evidence": [],
        }
    evidence: list[dict[str, object]] = []
    if score >= 3:
        evidence = [
            {
                "evidence_id": f"synthetic-evidence-{attribute_id}",
                "source_id": "synthetic-description-source",
                "lane": "DESCRIPTION",
                "dedup_cluster_id": f"synthetic-cluster-{attribute_id}",
                "direct": direct,
                "concordance_key": f"synthetic-theme-{attribute_id}",
                "supports_absence": False,
                "complete_context": False,
            }
        ]
    return {
        "attribute_id": attribute_id,
        "score": score,
        "unknown_reason": None,
        "unknown_note": None,
        "evidence": evidence,
    }


def _revision(
    capability: ModuleType,
    evaluator: str,
    *,
    overrides: dict[str, int | None] | None = None,
    primary_axis: str = "HISTORY_TRADITION",
    direct_overrides: dict[str, bool] | None = None,
) -> Any:
    overrides = overrides or {}
    direct_overrides = direct_overrides or {}
    return capability.RawLabelRevision.model_validate(
        {
            "assignment_id": "synthetic-assignment-alpha",
            "evaluator_pseudonym": evaluator,
            "primary_axis_judgment": primary_axis,
            "rubric_version": "synthetic-rubric-v1",
            "source_snapshot_version": "synthetic-source-v1",
            "parent_revision_sha256": None,
            "correction_reason": None,
            "judgments": [
                _judgment(
                    attribute_id,
                    overrides.get(attribute_id, 2),
                    direct=direct_overrides.get(attribute_id, True),
                )
                for attribute_id in ATTRIBUTE_IDS
            ],
            "submitted_at": SUBMITTED_AT,
        }
    )


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("clean", frozenset()),
        ("range-two", frozenset({("ATTRIBUTE_RANGE_AT_LEAST_TWO", "H1")})),
        ("primary-disagreement", frozenset({("ALL_PRIMARY_AXES_DIFFER", None)})),
        ("required-evidence", frozenset({("REQUIRED_EVIDENCE_MISSING", "H1")})),
    ],
)
def test_review_trigger_truth_table_has_exact_precision_and_recall(
    case: str, expected: frozenset[tuple[str, str | None]]
) -> None:
    capability = _capability()
    revisions = [
        _revision(capability, "synthetic-evaluator-a"),
        _revision(capability, "synthetic-evaluator-b"),
        _revision(capability, "synthetic-evaluator-c"),
    ]
    if case == "range-two":
        revisions[0] = _revision(capability, "synthetic-evaluator-a", overrides={"H1": 1})
        revisions[2] = _revision(capability, "synthetic-evaluator-c", overrides={"H1": 3})
    elif case == "primary-disagreement":
        revisions = [
            _revision(
                capability,
                "synthetic-evaluator-a",
                primary_axis="HISTORY_TRADITION",
            ),
            _revision(
                capability,
                "synthetic-evaluator-b",
                primary_axis="EMOTION_IMAGE",
            ),
            _revision(
                capability,
                "synthetic-evaluator-c",
                primary_axis="REST_IMMERSION",
            ),
        ]
    elif case == "required-evidence":
        revisions[1] = _revision(
            capability,
            "synthetic-evaluator-b",
            overrides={"H1": 3},
            direct_overrides={"H1": False},
        )

    actual = frozenset(
        (trigger.kind.value, trigger.attribute_id)
        for trigger in capability.derive_review_triggers(tuple(revisions))
    )
    true_positives = len(actual & expected)
    precision = true_positives / len(actual) if actual else 1.0
    recall = true_positives / len(expected) if expected else 1.0

    assert actual == expected
    assert precision == 1.00
    assert recall == 1.00


def test_range_trigger_is_inclusive_and_unknown_does_not_become_zero() -> None:
    capability = _capability()
    revisions = (
        _revision(capability, "synthetic-evaluator-a", overrides={"H1": None}),
        _revision(capability, "synthetic-evaluator-b", overrides={"H1": 1}),
        _revision(capability, "synthetic-evaluator-c", overrides={"H1": 3}),
    )

    triggers = capability.derive_review_triggers(revisions)

    assert any(
        trigger.kind.value == "ATTRIBUTE_RANGE_AT_LEAST_TWO" and trigger.attribute_id == "H1"
        for trigger in triggers
    )
    assert all(trigger.observed_numeric_values == (1, 3) for trigger in triggers)


def test_primary_axis_trigger_requires_three_distinct_judgments() -> None:
    capability = _capability()
    two_distinct = (
        _revision(capability, "synthetic-evaluator-a", primary_axis="HISTORY_TRADITION"),
        _revision(capability, "synthetic-evaluator-b", primary_axis="EMOTION_IMAGE"),
        _revision(capability, "synthetic-evaluator-c", primary_axis="EMOTION_IMAGE"),
    )

    assert all(
        trigger.kind.value != "ALL_PRIMARY_AXES_DIFFER"
        for trigger in capability.derive_review_triggers(two_distinct)
    )


def test_required_evidence_trigger_cannot_be_suppressed_by_indirect_evidence() -> None:
    capability = _capability()
    revisions = (
        _revision(capability, "synthetic-evaluator-a", overrides={"H1": 3}),
        _revision(
            capability,
            "synthetic-evaluator-b",
            overrides={"H1": 3},
            direct_overrides={"H1": False},
        ),
        _revision(capability, "synthetic-evaluator-c", overrides={"H1": 3}),
    )

    triggers = capability.derive_review_triggers(revisions)

    assert any(
        trigger.kind.value == "REQUIRED_EVIDENCE_MISSING" and trigger.attribute_id == "H1"
        for trigger in triggers
    )
