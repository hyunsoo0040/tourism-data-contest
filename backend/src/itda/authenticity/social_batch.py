"""Paired pilot-only count/meaning additions to frozen official/photo judgments."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from itda.authenticity.batch import store_versioned, write_once
from itda.authenticity.binding import bind_response
from itda.authenticity.contracts import Assessment, Judgment, Policy, SourceBundle
from itda.authenticity.model import TEXT_INSTRUCTIONS, GlmClient, ModelExchangeError, text_request
from itda.authenticity.review import bounded_exchange, review_assessment
from itda.authenticity.rubric import RUBRIC_PAYLOAD, FacetKey
from itda.authenticity.scoring import build_assessment, verify_assessment
from itda.authenticity.social_evidence import load_pilot_evidence
from itda.authenticity.sources import extend_source
from itda.domain.canonical import canonical_sha256
from itda.photo.model_control import ModelBatchControl, ModelBatchPaused
from itda.pipeline.destination_evidence import atomic_json

SOCIAL_KEYS: frozenset[FacetKey] = frozenset({"E.a", "E.b"})
SOCIAL_ANALYSIS_VERSION = "authenticity-social-meaning-v1"


def meaning_request(source: SourceBundle) -> tuple[dict[str, Any], SourceBundle]:
    payload, bound = text_request(source)
    schema = Judgment.model_json_schema()
    definitions = schema.pop("$defs", {})
    schema["properties"]["key"] = {"type": "string", "enum": sorted(SOCIAL_KEYS)}
    wire = {
        "type": "object",
        "additionalProperties": False,
        "required": ["judgments"],
        "properties": {
            "judgments": {"type": "array", "minItems": 2, "maxItems": 2, "items": schema}
        },
        "$defs": definitions,
    }
    payload["messages"][0]["content"] = (
        TEXT_INSTRUCTIONS.replace(
            "12개 새 항목을 한 번씩 반환하세요.", "E.a와 E.b만 한 번씩 반환하세요."
        )
        + json.dumps(RUBRIC_PAYLOAD, ensure_ascii=False)
        + json.dumps(wire, ensure_ascii=False)
    )
    payload["messages"][0]["content"] += (
        " 이번 요청에서는 E.a와 E.b만 한 번씩 반환하세요. 다른 항목은 반환하지 마세요."
        " 공식 설명과 함께 공개 SNS 본문이 장소에 부여한 이미지·의미를 평가하세요."
        " SNS의 방문 주장이나 감정은 객관적인 현장 사실로 확대하지 마세요."
        " SNS를 반영하는 판단은 해당 본문의 정확한 구절을 인용하세요."
        " 장소 이름이나 태그만 있는 것은 구체적인 구성적 의미가 아닙니다."
        " 광고·협찬·작성 주체 미확인도 표현의 출처로 구분하고"
        " 사회 전체가 공유하는 이미지나 실제 방문 여부라고 단정하지 마세요."
    )
    payload["max_tokens"] = 4096
    return payload, bound


def merge_meaning(
    original: Assessment, *, source: SourceBundle, output: object
) -> tuple[Assessment, dict[str, Any]]:
    """Only socially anchored E.a/E.b proposals may replace official judgments."""
    verify_assessment(original)
    proposed, rejected = bind_response(output, source)
    social_ids = {
        e.evidence_id
        for e in source.evidence
        if e.receipt.provider == "APIFY_INSTAGRAM" and e.modality == "TEXT"
    }
    replacements = {
        j.key: j
        for j in proposed
        if j.key in SOCIAL_KEYS
        and j.state == "SUPPORTED"
        and any(c.evidence_id in social_ids for c in j.citations)
    }
    result = build_assessment(
        source=source,
        judgments=tuple(replacements.get(j.key, j) for j in original.judgments),
        # Failed additional proposals are audited separately; they do not erase
        # previously bound official judgments or become new asserted facts.
        rejections=original.rejections,
        policy=Policy.model_validate(
            original.policy.model_dump() | {"social_mode": "COUNT_AND_MEANING"}
        ),
        model_request_sha256=None,
        assessed_at=original.assessed_at,
    )
    verify_assessment(result)
    return result, {
        "replaced_keys": sorted(replacements),
        "rejected_additional_proposals": [
            r.model_dump(mode="json") for r in rejected if r.key in SOCIAL_KEYS
        ],
        "preserved_keys": [j.key for j in original.judgments if j.key not in replacements],
        "lineage": "FROZEN_OFFICIAL_PHOTO_PLUS_SOCIAL_ANCHORED_E_A_E_B",
    }


def run_social_batch(
    *,
    directory: Path,
    pilot_directory: Path,
    api_key: str,
    photo_condition: str = "photo-er",
    workers: int = 5,
    live: bool = False,
) -> dict[str, Any]:
    if type(workers) is not int or not 1 <= workers <= 5:
        raise ValueError("USER_MODEL_CONCURRENCY_LIMIT_IS_FIVE")
    if photo_condition not in {"text", "photo-er", "photo-her"}:
        raise ValueError("SOCIAL_PHOTO_CONDITION_INVALID")
    manifest = json.loads((directory / "manifest.json").read_text())
    if manifest["manifest_sha256"] != canonical_sha256(
        {k: v for k, v in manifest.items() if k != "manifest_sha256"}
    ):
        raise ValueError("MANIFEST_DIGEST_MISMATCH")
    originals = []
    for member in manifest["members"]:
        stem = member["place_id"].split(":")[-1]
        assessment = Assessment.model_validate_json(
            (directory / "final-assessments" / photo_condition / (stem + ".json")).read_bytes()
        )
        verify_assessment(assessment)
        if assessment.source.place.place_id != member["place_id"]:
            raise ValueError("SOCIAL_BASELINE_MEMBERSHIP_CHANGED")
        originals.append(assessment)
    control = ModelBatchControl(
        retry_limits=True,
        retry_connections=True,
        on_retry=lambda state: atomic_json(directory / "social/model-state.json", state),
    )
    client = GlmClient(api_key=api_key, control=control)
    plan = {
        "version": SOCIAL_ANALYSIS_VERSION,
        "parent_manifest_sha256": manifest["manifest_sha256"],
        "photo_condition": photo_condition,
        "baseline_assessment_sha256": [a.assessment_sha256 for a in originals],
        "pilot_association_report_sha256": canonical_sha256(
            json.loads((pilot_directory / "association-report.json").read_text())
        ),
        "count_condition": "FROZEN_BASELINE_PLUS_VALIDATED_COUNT_NO_CAPTIONS",
        "meaning_condition": "SAME_BASELINE_PLUS_SOCIAL_ANCHORED_E_A_E_B_AND_COUNT",
        "human_evaluation": "EXCLUDED_BY_USER",
    }
    plan["plan_sha256"] = canonical_sha256(plan)
    write_once(directory / "social/plan.json", plan)

    def analyze(original: Assessment) -> dict[str, Any]:
        control.check()
        pid = original.source.place.place_id
        stem = pid.split(":")[-1]
        records = load_pilot_evidence(pilot_directory, original.source)
        counts = tuple(e for e in records if e.modality == "COUNT")
        count = build_assessment(
            source=extend_source(original.source, counts),
            judgments=original.judgments,
            rejections=original.rejections,
            policy=Policy.model_validate(original.policy.model_dump() | {"social_mode": "COUNT"}),
            model_request_sha256=original.model_request_sha256,
            assessed_at=original.assessed_at,
        )
        source = extend_source(original.source, records)
        model: dict[str, Any] | None = None
        review: dict[str, Any] | None = None
        if any(e.modality == "TEXT" for e in records):
            payload, bounded = meaning_request(source)
            # Official source records were already frozen and bounded. Require
            # identity before reusing their quote offsets in the combined source.
            by_id = {e.evidence_id: e for e in bounded.evidence}
            for e in original.source.evidence:
                if e.modality == "TEXT" and by_id.get(e.evidence_id) != e:
                    raise ValueError("SOCIAL_REQUEST_CHANGED_OFFICIAL_TEXT")
            combined = extend_source(
                bounded, tuple(e for e in source.evidence if e.modality != "TEXT")
            )
            output, model = bounded_exchange(
                client,
                payload,
                directory=directory / "social/model-cache",
                live=live,
                response_key="judgments",
            )
            if not isinstance(output, dict) or not isinstance(output.get("judgments"), list):
                output = {"judgments": []}
                model = {**model, "social_response_status": "INVALID_ENVELOPE"}
            meaning, audit = merge_meaning(original, source=combined, output=output)
            meaning, review = review_assessment(
                meaning,
                client=client,
                directory=directory / "social/semantic-review",
                live=live,
                only_keys=frozenset(k for k in SOCIAL_KEYS if k in audit["replaced_keys"]),
            )
        else:
            meaning, audit = merge_meaning(original, source=source, output={"judgments": []})
            audit["status"] = "NO_ASSOCIATED_CAPTION"
        for folder, assessment in (("social-count", count), ("social-meaning", meaning)):
            verify_assessment(assessment)
            store_versioned(
                directory / "final-assessments" / folder / (stem + ".json"),
                assessment.model_dump(mode="json"),
                hash_field="assessment_sha256",
            )
        row = {
            "place_id": pid,
            "name_ko": original.source.place.name_ko,
            "baseline_sha256": original.assessment_sha256,
            "count_sha256": count.assessment_sha256,
            "meaning_sha256": meaning.assessment_sha256,
            "caption_records": sum(e.modality == "TEXT" for e in records),
            "usable_counts": sum(e.state == "AVAILABLE" for e in counts),
            "model": model,
            "merge": audit,
            "review": review,
        }
        atomic_json(directory / "social/audits" / (stem + ".json"), row)
        return row

    rows = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(analyze, a) for a in originals]
        try:
            for future in as_completed(futures):
                row = future.result()
                rows.append(row)
                print(
                    json.dumps(
                        {
                            "stage": "SOCIAL_ABLATION",
                            "completed": len(rows),
                            "total": len(futures),
                            "place": row["name_ko"],
                        },
                        ensure_ascii=False,
                    ),
                    flush=True,
                )
        except (ModelBatchPaused, ModelExchangeError):
            for future in futures:
                future.cancel()
            raise
    report = {
        "schema_version": SOCIAL_ANALYSIS_VERSION,
        "plan_sha256": plan["plan_sha256"],
        "completed_at": datetime.now(UTC).isoformat(),
        "places": len(rows),
        "caption_places": sum(r["caption_records"] > 0 for r in rows),
        "scope": "PILOT_ONLY_AUTOMATIC_AND_AI_ASSISTED_NOT_HUMAN_LABELS",
        "rows": sorted(rows, key=lambda r: r["place_id"]),
    }
    report["report_sha256"] = canonical_sha256(report)
    atomic_json(directory / "social/summary.json", report)
    return report
