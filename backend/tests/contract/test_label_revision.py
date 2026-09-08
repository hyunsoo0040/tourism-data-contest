"""Wave 0 RED contracts for the independent Phase 3 labeling rubric."""

from __future__ import annotations

import importlib
import importlib.util
import json
from copy import deepcopy
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from pydantic import ValidationError

CAPABILITY_MODULE = "itda.contracts.labeling"
FIXTURE_PATH = Path(__file__).resolve().parents[3] / "fixtures/synthetic/phase3/labeling.json"
EXPECTED_ATTRIBUTE_ORDER = (
    "H1",
    "H2",
    "H3",
    "H4",
    "I1",
    "I2",
    "I3",
    "I4",
    "R1",
    "R2",
    "R3",
    "R4",
)
EXPECTED_UNKNOWN_REASONS = (
    "NO_EVIDENCE",
    "INSUFFICIENT_EVIDENCE",
    "CONFLICTING_EVIDENCE",
    "OUT_OF_SCOPE_INFORMATION",
)
EXPECTED_SCORE_MEANINGS = ("ABSENT", "WEAK", "MODERATE", "STRONG", "DOMINANT")
BOUNDARY_ASCII_WHITESPACE = " \t\n\r\f\v"


def _capability() -> ModuleType:
    if importlib.util.find_spec(CAPABILITY_MODULE) is None:
        pytest.fail("PHASE3-MISSING:labeling-contract", pytrace=False)
    return importlib.import_module(CAPABILITY_MODULE)


def _fixture() -> dict[str, Any]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _evidence(
    *,
    evidence_id: str,
    lane: str = "DESCRIPTION",
    cluster: str = "synthetic-cluster-a",
    direct: bool = True,
    concordance_key: str = "synthetic-theme-a",
    supports_absence: bool = False,
    complete_context: bool = False,
) -> dict[str, object]:
    return {
        "evidence_id": evidence_id,
        "source_id": f"synthetic-{lane.lower()}-source",
        "lane": lane,
        "dedup_cluster_id": cluster,
        "direct": direct,
        "concordance_key": concordance_key,
        "supports_absence": supports_absence,
        "complete_context": complete_context,
    }


def _judgment(
    *,
    score: int | None,
    unknown_reason: str | None = None,
    unknown_note: str | None = None,
    evidence: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "attribute_id": "H1",
        "score": score,
        "unknown_reason": unknown_reason,
        "unknown_note": unknown_note,
        "evidence": evidence or [],
    }


def test_raw_revision_correction_reason_must_be_trimmed() -> None:
    capability = _capability()
    payload = {
        "assignment_id": "synthetic-assignment-alpha",
        "evaluator_pseudonym": "synthetic-evaluator-alpha",
        "primary_axis": None,
        "rubric_version": "synthetic-rubric-v1",
        "source_snapshot_version": "synthetic-source-v1",
        "parent_revision_sha256": "a" * 64,
        "correction_reason": " 앞뒤 공백 ",
        "submitted_at": "2026-08-03T00:00:00+00:00",
        "judgments": [
            {
                "attribute_id": attribute_id,
                "score": 2,
                "unknown_reason": None,
                "unknown_note": None,
                "evidence": [],
            }
            for attribute_id in EXPECTED_ATTRIBUTE_ORDER
        ],
    }

    with pytest.raises(ValidationError, match="correction reason must be trimmed"):
        capability.RawLabelRevision.model_validate(payload)


def test_rubric_uses_exact_order_common_anchors_and_nonempty_korean_guidance() -> None:
    capability = _capability()
    fixture = _fixture()
    specs = capability.LABEL_RUBRIC_SPECS

    assert tuple(spec.attribute_id for spec in specs) == EXPECTED_ATTRIBUTE_ORDER
    assert tuple(anchor.score for anchor in capability.SCORE_ANCHORS) == tuple(range(5))
    assert tuple(anchor.meaning_code for anchor in capability.SCORE_ANCHORS) == (
        EXPECTED_SCORE_MEANINGS
    )
    assert tuple(reason.value for reason in capability.UnknownReason) == EXPECTED_UNKNOWN_REASONS
    assert [spec.model_dump(mode="json") for spec in specs] == fixture["rubric"]["subattributes"]
    assert all(spec.examples_ko and spec.counterexamples_ko for spec in specs)
    assert all(
        value.strip() for spec in specs for value in (*spec.examples_ko, *spec.counterexamples_ko)
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "extra",
        "reordered",
        "empty-examples",
        "empty-counterexamples",
    ],
)
def test_rubric_rejects_shape_order_and_empty_guidance(mutation: str) -> None:
    capability = _capability()
    rows = deepcopy(_fixture()["rubric"]["subattributes"])
    if mutation == "missing":
        rows.pop()
    elif mutation == "extra":
        rows.append(deepcopy(rows[-1]))
    elif mutation == "reordered":
        rows[0], rows[1] = rows[1], rows[0]
    elif mutation == "empty-examples":
        rows[0]["examples_ko"] = []
    else:
        rows[0]["counterexamples_ko"] = ["   "]

    with pytest.raises(ValidationError):
        capability.LabelRubric.model_validate({"subattributes": rows})


@pytest.mark.parametrize("note", ["가", "가" * 300])
def test_unknown_requires_closed_reason_and_trimmed_bounded_note(note: str) -> None:
    capability = _capability()

    judgment = capability.AttributeJudgment.model_validate(
        _judgment(score=None, unknown_reason="NO_EVIDENCE", unknown_note=note)
    )

    assert judgment.score is None
    assert judgment.unknown_reason.value == "NO_EVIDENCE"
    assert judgment.unknown_note == note


@pytest.mark.parametrize("note", [True, 7, 3.5])
def test_unknown_note_requires_a_json_string(note: object) -> None:
    capability = _capability()
    payload = _judgment(score=None, unknown_reason="NO_EVIDENCE", unknown_note=None)
    payload["unknown_note"] = note

    with pytest.raises(ValidationError):
        capability.AttributeJudgment.model_validate_json(
            json.dumps(payload, ensure_ascii=False)
        )


@pytest.mark.parametrize("note", ["true", "7", "3.5"])
def test_unknown_note_accepts_json_string_lexemes(note: str) -> None:
    capability = _capability()

    judgment = capability.AttributeJudgment.model_validate_json(
        json.dumps(
            _judgment(score=None, unknown_reason="NO_EVIDENCE", unknown_note=note),
            ensure_ascii=False,
        )
    )

    assert judgment.unknown_note == note


@pytest.mark.parametrize(
    "note",
    [f"{boundary}합성 설명" for boundary in BOUNDARY_ASCII_WHITESPACE]
    + [f"합성 설명{boundary}" for boundary in BOUNDARY_ASCII_WHITESPACE],
)
def test_unknown_note_rejects_boundary_ascii_whitespace(note: str) -> None:
    capability = _capability()

    with pytest.raises(ValidationError, match="unknown note must be trimmed"):
        capability.AttributeJudgment.model_validate(
            _judgment(score=None, unknown_reason="NO_EVIDENCE", unknown_note=note)
        )


@pytest.mark.parametrize("note", ["\u00a0합성 설명\u2003", "\u00a0\u2003"])
def test_unknown_note_deliberately_preserves_unicode_boundary_whitespace(note: str) -> None:
    capability = _capability()

    judgment = capability.AttributeJudgment.model_validate(
        _judgment(score=None, unknown_reason="NO_EVIDENCE", unknown_note=note)
    )

    assert judgment.unknown_note == note


@pytest.mark.parametrize(
    ("reason", "note"),
    [
        (None, "합성 설명"),
        ("UNKNOWN_REASON", "합성 설명"),
        ("NO_EVIDENCE", None),
        ("NO_EVIDENCE", ""),
        ("NO_EVIDENCE", "   "),
        ("NO_EVIDENCE", "가" * 301),
    ],
)
def test_unknown_rejects_open_reason_and_invalid_note(reason: str | None, note: str | None) -> None:
    capability = _capability()

    with pytest.raises(ValidationError):
        capability.AttributeJudgment.model_validate(
            _judgment(score=None, unknown_reason=reason, unknown_note=note)
        )


@pytest.mark.parametrize("score", range(5))
def test_present_score_forbids_unknown_reason_and_note(score: int) -> None:
    capability = _capability()

    with pytest.raises(ValidationError):
        capability.AttributeJudgment.model_validate(
            _judgment(
                score=score,
                unknown_reason="NO_EVIDENCE",
                unknown_note="합성 설명",
            )
        )


def test_score_three_requires_at_least_one_direct_evidence_item() -> None:
    capability = _capability()
    accepted = capability.AttributeJudgment.model_validate(
        _judgment(score=3, evidence=[_evidence(evidence_id="synthetic-direct")])
    )

    assert accepted.score == 3
    with pytest.raises(ValidationError):
        capability.AttributeJudgment.model_validate(_judgment(score=3))
    with pytest.raises(ValidationError):
        capability.AttributeJudgment.model_validate(
            _judgment(
                score=3,
                evidence=[_evidence(evidence_id="synthetic-indirect", direct=False)],
            )
        )


def test_score_four_accepts_two_distinct_direct_clusters_in_one_lane() -> None:
    capability = _capability()

    judgment = capability.AttributeJudgment.model_validate(
        _judgment(
            score=4,
            evidence=[
                _evidence(evidence_id="synthetic-a", cluster="synthetic-cluster-a"),
                _evidence(evidence_id="synthetic-b", cluster="synthetic-cluster-b"),
            ],
        )
    )

    assert judgment.score == 4


def test_score_four_accepts_two_distinct_direct_clusters_across_lanes() -> None:
    capability = _capability()

    judgment = capability.AttributeJudgment.model_validate(
        _judgment(
            score=4,
            evidence=[
                _evidence(evidence_id="synthetic-description"),
                _evidence(
                    evidence_id="synthetic-odii",
                    lane="ODII",
                    cluster="synthetic-cluster-c",
                    concordance_key="synthetic-theme-z",
                ),
            ],
        )
    )

    assert judgment.score == 4


def test_score_four_rejects_duplicate_cluster_across_lanes_and_concordance_keys() -> None:
    capability = _capability()

    with pytest.raises(ValidationError):
        capability.AttributeJudgment.model_validate(
            _judgment(
                score=4,
                evidence=[
                    _evidence(evidence_id="synthetic-first"),
                    _evidence(
                        evidence_id="synthetic-second",
                        lane="ODII",
                        cluster="synthetic-cluster-a",
                        concordance_key="synthetic-theme-z",
                    ),
                ],
            )
        )


@pytest.mark.parametrize("proof_kind", ["counterevidence", "complete-context"])
def test_zero_requires_positive_absence_proof(proof_kind: str) -> None:
    capability = _capability()
    proof = _evidence(
        evidence_id="synthetic-zero-proof",
        supports_absence=proof_kind == "counterevidence",
        complete_context=proof_kind == "complete-context",
    )

    judgment = capability.AttributeJudgment.model_validate(_judgment(score=0, evidence=[proof]))

    assert judgment.score == 0
    with pytest.raises(ValidationError):
        capability.AttributeJudgment.model_validate(
            _judgment(score=0, evidence=[_evidence(evidence_id="synthetic-no-proof")])
        )
