"""Partial response diagnostics, exact source binding and conservative semantic screens."""

from __future__ import annotations

import re
from typing import Any

from pydantic import ValidationError

from itda.authenticity.authority import authorizes_text
from itda.authenticity.contracts import (
    BoundCitation,
    BoundJudgment,
    Judgment,
    Rejection,
    SourceBundle,
)
from itda.authenticity.quotes import match_quote, verify_quote
from itda.authenticity.rubric import FACET_KEYS, FacetKey

# These screens catch known failure patterns; they are not ground-truth entailment tests.
_ABSENCE_REASON = re.compile(
    r"(?:근거|묘사|설명|서술|언급|정보).{0,18}(?:없|부족|제공되지|확인되지)|"
    r"(?:언급|명시|서술|제공)되지\s*않|추정(?:되|할|하)"
)
_OTHER_SUBJECT = re.compile(
    r"(?:제작사|운영사).{0,24}(?:실적|납품)|다른\s*(?:박물관|전시관).{0,20}제작"
)


def unknown(key: FacetKey, reason: str, *, rejected: bool = False) -> BoundJudgment:
    return BoundJudgment(
        key=key,
        state="REJECTED" if rejected else "UNKNOWN",
        level=None,
        citations=(),
        reason=reason,
    )


def bind_one(judgment: Judgment, source: SourceBundle) -> BoundJudgment:
    if judgment.state == "UNKNOWN":
        return unknown(judgment.key, judgment.reason)
    by_id = {record.evidence_id: record for record in source.evidence}
    citations = []
    for citation in judgment.citations:
        record = by_id.get(citation.evidence_id)
        if record is None:
            raise ValueError("CITATION_SOURCE_NOT_BOUND")
        if record.place_id != source.place.place_id:
            raise ValueError("CITATION_PLACE_MISMATCH")
        if not authorizes_text(record, judgment.key, citation.claim):
            raise ValueError("SOURCE_CLAIM_FACET_NOT_AUTHORIZED")
        if record.text is None:
            raise ValueError("TEXT_CITATION_HAS_NO_TEXT")
        quote = match_quote(record.text, citation.quote)
        citations.append(
            BoundCitation(
                evidence_id=record.evidence_id,
                record_sha256=record.record_sha256,
                claim=citation.claim,
                quote=quote,
            )
        )
    if judgment.level == 0 and _ABSENCE_REASON.search(judgment.reason):
        raise ValueError("ABSENCE_OF_EVIDENCE_IS_NOT_ZERO")
    if judgment.key.startswith("H") and _OTHER_SUBJECT.search(judgment.reason):
        raise ValueError("OTHER_SUBJECT_HISTORY_TRANSFER")
    flags = ("INFERENCE_SCOPE_REVIEW",) if _ABSENCE_REASON.search(judgment.reason) else ()
    return BoundJudgment(
        key=judgment.key,
        state="SUPPORTED",
        level=judgment.level,
        citations=tuple(citations),
        reason=judgment.reason,
        flags=flags,
    )


def bind_response(
    payload: object,
    source: SourceBundle,
) -> tuple[tuple[BoundJudgment, ...], tuple[Rejection, ...]]:
    if not isinstance(payload, dict) or set(payload) != {"judgments"}:
        raise ValueError("AUTHENTICITY_RESPONSE_ENVELOPE_INVALID")
    rows = payload["judgments"]
    if not isinstance(rows, list) or len(rows) > 48:
        raise ValueError("AUTHENTICITY_JUDGMENTS_INVALID")
    rejections: list[Rejection] = []
    grouped: dict[str, list[dict[str, Any]]] = {}
    for raw in rows:
        if not isinstance(raw, dict) or raw.get("key") not in FACET_KEYS:
            rejections.append(
                Rejection(
                    key=None,
                    code="UNKNOWN_FACET",
                    reason="새 버전의 항목 ID가 아닙니다.",
                    proposed={"raw": raw},
                )
            )
            continue
        grouped.setdefault(raw["key"], []).append(raw)
    results = []
    for key in FACET_KEYS:
        proposals = grouped.get(key, [])
        if len(proposals) != 1:
            code = "MISSING_FACET" if not proposals else "DUPLICATED_FACET"
            rejections.append(
                Rejection(key=key, code=code, reason=code, proposed={"rows": proposals})
            )
            results.append(unknown(key, code, rejected=True))
            continue
        raw = proposals[0]
        try:
            parsed = Judgment.model_validate(raw)
            result = bind_one(parsed, source)
        except ValidationError as error:
            code = "FACET_SCHEMA_REJECTED"
            reasons = "; ".join(e["msg"] for e in error.errors(include_input=False))
            rejections.append(Rejection(key=key, code=code, reason=reasons, proposed=raw))
            result = unknown(key, reasons, rejected=True)
        except ValueError as error:
            code = str(error)
            rejections.append(Rejection(key=key, code=code, reason=code, proposed=raw))
            result = unknown(key, code, rejected=True)
        results.append(result)
    return tuple(results), tuple(rejections)


def verify_bound(judgment: BoundJudgment, source: SourceBundle) -> None:
    BoundJudgment.model_validate_json(judgment.model_dump_json())
    for citation in judgment.citations:
        record = next((r for r in source.evidence if r.evidence_id == citation.evidence_id), None)
        if record is None or record.record_sha256 != citation.record_sha256:
            raise ValueError("BOUND_CITATION_RECORD_MISMATCH")
        if not authorizes_text(record, judgment.key, citation.claim) or record.text is None:
            raise ValueError("BOUND_CITATION_AUTHORITY_INVALID")
        verify_quote(record.text, citation.quote)
