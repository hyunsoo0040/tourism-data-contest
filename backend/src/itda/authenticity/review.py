"""AI-assisted semantic screening, explicitly not human labels or ground truth."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import Field, ValidationError, model_validator

from itda.authenticity.batch import store_versioned
from itda.authenticity.binding import bind_response, unknown
from itda.authenticity.contracts import Assessment, Judgment, Rejection
from itda.authenticity.model import (
    MODEL,
    TEXT_INSTRUCTIONS,
    GlmClient,
    ModelExchangeError,
    text_request,
)
from itda.authenticity.rubric import FACET_BY_KEY, FACET_KEYS, RUBRIC_PAYLOAD, FacetKey
from itda.authenticity.scoring import build_assessment, verify_assessment
from itda.contracts.base import StrictContract
from itda.domain.canonical import canonical_sha256
from itda.pipeline.destination_evidence import atomic_json


class SemanticDecision(StrictContract):
    key: FacetKey
    decision: Literal["SUPPORTED", "REJECTED", "UNCERTAIN"]
    issues: tuple[
        Literal[
            "WRONG_SUBJECT",
            "WRONG_FACET",
            "UNSUPPORTED_INFERENCE",
            "ZERO_FROM_MISSING",
            "ORIGINAL_REPLICA_CONFUSION",
            "BUSINESS_AS_TOURIST_ACTIVITY",
            "MARKETING_AS_FIELD_FACT",
            "INSUFFICIENT_CONTEXT",
        ],
        ...,
    ]
    reason: str = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if self.decision == "SUPPORTED" and set(self.issues) - {"INSUFFICIENT_CONTEXT"}:
            raise ValueError("SEMANTIC_DECISION_ISSUE_MISMATCH")
        if self.decision != "SUPPORTED" and not self.issues:
            raise ValueError("SEMANTIC_DECISION_ISSUE_MISMATCH")
        return self


class SemanticWire(StrictContract):
    reviews: tuple[SemanticDecision, ...] = Field(max_length=12)

    @model_validator(mode="after")
    def unique(self) -> Self:
        if len({r.key for r in self.reviews}) != len(self.reviews):
            raise ValueError("SEMANTIC_REVIEW_DUPLICATED_FACET")
        return self


REVIEW_INSTRUCTIONS = " ".join(
    (
        "독립된 검토 요청으로 제안된 항목의 근거와 해석을 점검하세요.",
        "이 검토는 AI 보조 검사이며 인간 정답·실제 만족도를 대신하지 않습니다.",
        "원문을 먼저 읽고 해당 장소·해당 항목·해당 강도를 직접 뒷받침하는지 확인하세요.",
        "인용이 원문에 있다는 사실만으로 의미가 맞다고 하지 마세요.",
        "제작사나 인근 장소의 특성을 현재 장소에 옮겼으면 거부하세요.",
        "일반 학습·상업 서비스·내부 업무를 관광객의 역사 경험이나 참여 활동으로 확대하지 마세요.",
        "현재 산업 활동이 존재한다는 사실만으로 원형 유산·문화 전승이라고 단정하지 마세요.",
        "원형·복원·재현을 구분하세요. 오래돼 보인다는 것은 역사적 진위가 아닙니다.",
        "0점에 자료 부재를 사용했거나 홍보 표현으로 실제 고요함·회복을 단정하면 거부하세요.",
        "E는 대상의 사회적 이미지와 표현·재현이며, 단순 유명세·예쁨과 동일하지 않습니다.",
        "R은 활동·환경의 기회이지 내면의 자유·몰입을 이미 경험했다는 사실이 아닙니다.",
        "판단하기 어려우면 UNCERTAIN으로 남기세요. 확신을 만들지 마세요.",
        "제안된 SUPPORTED 항목만 정확히 한 번씩 검토하고 JSON을 반환하세요.",
        "각 항목의 anchor_ko는 현재 제안 수준의 정확한 앵커입니다. 반드시 대조하세요.",
        "상위 수준의 근거 부족을 현재 낮은 수준의 부적합으로 혼동하지 마세요.",
        "SUPPORTED에는 문제 코드가 없거나 상위 수준의 한계인 INSUFFICIENT_CONTEXT만 가능합니다.",
        "현재 수준도 뒷받침되지 않으면 REJECTED 또는 UNCERTAIN과 문제 코드를 반환하세요.",
    )
)


def normalize_review(
    output: object,
    keys: set[FacetKey],
) -> tuple[tuple[SemanticDecision, ...], dict[FacetKey, list[dict[str, Any]]]]:
    if (
        not isinstance(output, dict)
        or set(output) != {"reviews"}
        or not isinstance(output["reviews"], list)
    ):
        raise ValueError("SEMANTIC_REVIEW_ENVELOPE_INVALID")
    grouped: dict[FacetKey, list[dict[str, Any]]] = {key: [] for key in keys}
    for raw in output["reviews"]:
        if isinstance(raw, dict) and raw.get("key") in grouped:
            grouped[raw["key"]].append(raw)
    decisions = []
    invalid = {}
    for key in FACET_KEYS:
        if key not in keys:
            continue
        rows = grouped[key]
        try:
            if len(rows) != 1:
                raise ValueError("MISSING_OR_DUPLICATED_REVIEW")
            decision = SemanticDecision.model_validate(rows[0])
        except (ValidationError, ValueError):
            invalid[key] = rows
            decision = SemanticDecision(
                key=key,
                decision="UNCERTAIN",
                issues=("INSUFFICIENT_CONTEXT",),
                reason="AI 검토 응답의 누락·중복·형식 모순으로 판단을 확정하지 않았습니다.",
            )
        decisions.append(decision)
    return tuple(decisions), invalid


def _request(system: str, user: dict[str, Any]) -> dict[str, Any]:
    return {
        "model": MODEL,
        "stream": False,
        "max_tokens": 8192,
        "thinking": {"type": "disabled"},
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(user, ensure_ascii=False)},
        ],
    }


def bounded_exchange(
    client: GlmClient,
    payload: dict[str, Any],
    *,
    directory: Path,
    live: bool,
    response_key: Literal["reviews", "judgments"] = "reviews",
) -> tuple[object, dict[str, Any]]:
    """At most two recorded wire attempts; invalid AI review remains uncertain."""
    try:
        return client.complete(payload, directory=directory, live=False)
    except ModelExchangeError as error:
        if error.code != "OFFLINE_MODEL_CACHE_MISS" or not live:
            raise
    digest = canonical_sha256(payload)
    for _ in range(2):
        attempts = sorted(directory.glob(digest + "-*.attempt.json"))
        if len(attempts) >= 2:
            break
        try:
            return client.complete(payload, directory=directory, live=True)
        except ModelExchangeError as error:
            if error.code != "MODEL_JSON_RESPONSE_REJECTED":
                raise
    return {response_key: []}, {
        "status": "MODEL_WIRE_INVALID_AFTER_BOUNDED_ATTEMPTS",
        "request_sha256": digest,
        "attempt_records": [str(p) for p in sorted(directory.glob(digest + "-*.attempt.json"))],
    }


def review_assessment(
    assessment: Assessment,
    *,
    client: GlmClient,
    directory: Path,
    live: bool,
    only_keys: frozenset[FacetKey] | None = None,
) -> tuple[Assessment, dict[str, Any]]:
    verify_assessment(assessment)
    supported = [
        j
        for j in assessment.judgments
        if j.state == "SUPPORTED" and (only_keys is None or j.key in only_keys)
    ]
    keys = {j.key for j in supported}
    _, bound = text_request(assessment.source)
    if supported:
        user = {
            "place": assessment.source.place.model_dump(mode="json"),
            "source": [
                {
                    "id": e.evidence_id,
                    "provider": e.receipt.provider,
                    "field": e.field,
                    "text": e.text,
                }
                for e in bound.evidence
            ],
            "judgments": [
                j.model_dump(mode="json")
                | {
                    "anchor_ko": FACET_BY_KEY[j.key].anchors[j.level]
                    if j.level is not None
                    else None
                }
                for j in supported
            ],
        }
        prompt = (
            REVIEW_INSTRUCTIONS
            + json.dumps(RUBRIC_PAYLOAD, ensure_ascii=False)
            + json.dumps(SemanticWire.model_json_schema(), ensure_ascii=False)
        )
        output, meta = bounded_exchange(
            client, _request(prompt, user), directory=directory / "model-cache", live=live
        )
        decisions, invalid_rows = normalize_review(output, keys)
    else:
        meta = None
        decisions = ()
        invalid_rows = {}
    by_key = {d.key: d for d in decisions}
    retained = []
    exclusions = list(assessment.rejections)
    for original in assessment.judgments:
        decision = by_key.get(original.key)
        if decision is not None and decision.decision != "SUPPORTED":
            code = (
                "AI_SEMANTIC_REJECTED"
                if decision.decision == "REJECTED"
                else "AI_SEMANTIC_UNCERTAIN"
            )
            if original.key in invalid_rows:
                code = "AI_REVIEW_RESPONSE_INVALID"
            exclusions.append(
                Rejection(
                    key=original.key,
                    code=code,
                    reason=decision.reason,
                    proposed={
                        "original": original.model_dump(mode="json"),
                        "review": decision.model_dump(mode="json"),
                    },
                )
            )
            retained.append(unknown(original.key, decision.reason, rejected=True))
        else:
            if decision is not None and decision.issues:
                original = original.model_copy(
                    update={"flags": tuple(sorted(set(original.flags) | {"AI_LIMITED_CONTEXT"}))}
                )
            retained.append(original)
    result = build_assessment(
        source=assessment.source,
        judgments=tuple(retained),
        policy=assessment.policy,
        rejections=tuple(exclusions),
        model_request_sha256=assessment.model_request_sha256,
        assessed_at=assessment.assessed_at,
    )
    report: dict[str, Any] = {
        "schema_version": "authenticity-ai-semantic-review.v1",
        "input_assessment_sha256": assessment.assessment_sha256,
        "output_assessment_sha256": result.assessment_sha256,
        "model": meta,
        "reviews": [r.model_dump(mode="json") for r in decisions],
        "invalid_review_rows": invalid_rows,
        "scope": "AI_ASSISTED_NOT_INDEPENDENT_HUMAN_GROUND_TRUTH",
        "human_evaluation": "EXCLUDED_BY_USER",
    }
    report["report_sha256"] = canonical_sha256(report)
    atomic_json(directory / "reports" / (report["report_sha256"] + ".json"), report)
    return result, report


def repair_assessment(
    assessment: Assessment,
    *,
    original_wire: object,
    client: GlmClient,
    directory: Path,
    live: bool,
) -> tuple[Assessment, dict[str, Any]]:
    """Repair only rejected facets; never overwrite an already accepted judgment."""
    verify_assessment(assessment)
    rejected = {j.key for j in assessment.judgments if j.state == "REJECTED"}
    if not rejected:
        return assessment, {"status": "NO_REPAIR_REQUIRED", "requests": []}
    if not isinstance(original_wire, dict) or not isinstance(original_wire.get("judgments"), list):
        raise ValueError("REPAIR_REQUIRES_ORIGINAL_WIRE")
    original_bound, _ = bind_response(original_wire, assessment.source)
    expected = {j.key: j for j in assessment.judgments if j.key not in rejected}
    if any(j.key in expected and j != expected[j.key] for j in original_bound):
        raise ValueError("ORIGINAL_WIRE_DOES_NOT_MATCH_RETAINED_JUDGMENTS")
    base = {
        r["key"]: r
        for r in original_wire["judgments"]
        if isinstance(r, dict) and r.get("key") in FACET_KEYS
    }
    payload, _ = text_request(assessment.source)
    user = json.loads(payload["messages"][1]["content"])
    user["repair"] = [r.model_dump(mode="json") for r in assessment.rejections if r.key in rejected]
    schema = Judgment.model_json_schema()
    definitions = schema.pop("$defs", {})
    response_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "judgments": {
                "type": "array",
                "minItems": len(rejected),
                "maxItems": len(rejected),
                "items": schema,
            }
        },
        "required": ["judgments"],
        "$defs": definitions,
    }
    instructions = TEXT_INSTRUCTIONS.replace(
        "12개 새 항목을 한 번씩 반환하세요.", "repair 목록의 항목만 한 번씩 반환하세요."
    )
    instructions += " E.c의 텍스트 claim은 VISUAL_EXPRESSION입니다."
    instructions += " VISUAL_APPEARANCE는 픽셀 전용입니다."
    output, meta = bounded_exchange(
        client,
        _request(
            instructions
            + json.dumps(RUBRIC_PAYLOAD, ensure_ascii=False)
            + json.dumps(response_schema, ensure_ascii=False),
            user,
        ),
        directory=directory / "model-cache",
        live=live,
        response_key="judgments",
    )
    if not isinstance(output, dict) or not isinstance(output.get("judgments"), list):
        output = {"judgments": []}
        meta = {**meta, "repair_response_status": "REPAIR_RESPONSE_INVALID"}
    repair_rows: list[Any] = output["judgments"]
    grouped: dict[FacetKey, list[dict[str, Any]]] = {key: [] for key in rejected}
    ignored = []
    for row in repair_rows:
        if isinstance(row, dict) and row.get("key") in rejected:
            grouped[row["key"]].append(row)
        else:
            ignored.append(row)
    invalid_targets = []
    for key, rows in grouped.items():
        if len(rows) == 1:
            base[key] = rows[0]
        else:
            invalid_targets.append(key)
    # Out-of-scope model changes have no authority over retained judgments.
    combined = {"judgments": [base[k] for k in FACET_KEYS if k in base]}
    rebound, rejections = bind_response(combined, assessment.source)
    old = {j.key: j for j in assessment.judgments}
    retained = tuple(j if j.key in rejected else old[j.key] for j in rebound)
    result = build_assessment(
        source=assessment.source,
        judgments=retained,
        policy=assessment.policy,
        rejections=tuple(r for r in rejections if r.key in rejected),
        model_request_sha256=None,
        assessed_at=assessment.assessed_at,
    )
    report: dict[str, Any] = {
        "schema_version": "authenticity-targeted-repair.v1",
        "input_assessment_sha256": assessment.assessment_sha256,
        "output_assessment_sha256": result.assessment_sha256,
        "original_model_request_sha256": assessment.model_request_sha256,
        "repair_model": meta,
        "repaired_keys": sorted(rejected),
        "composed_wire_sha256": canonical_sha256(combined),
        "composed_wire": combined,
        "preserved_keys": [k for k in FACET_KEYS if k not in rejected],
        "analysis_lineage": "COMPOSITE_OF_RETAINED_ORIGINAL_AND_TARGETED_REPAIR",
        "ignored_out_of_scope_rows": ignored,
        "invalid_repair_targets": sorted(invalid_targets),
        "remaining_rejections": [
            r.model_dump(mode="json") for r in rejections if r.key in rejected
        ],
    }
    report["report_sha256"] = canonical_sha256(report)
    store_versioned(
        directory / "reports" / (assessment.source.place.place_id.split(":")[-1] + ".json"),
        report,
        hash_field="report_sha256",
    )
    return result, report
