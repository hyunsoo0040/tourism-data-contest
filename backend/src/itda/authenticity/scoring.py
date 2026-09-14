"""Deterministic, source-traced fusion; missing values and source counts never add points."""

from __future__ import annotations

import math
from datetime import datetime

from itda.authenticity.authority import allowed_claims
from itda.authenticity.binding import verify_bound
from itda.authenticity.contracts import (
    Assessment,
    AxisScore,
    BoundJudgment,
    Claim,
    Contribution,
    Evidence,
    FacetScore,
    Policy,
    Rejection,
    SourceBundle,
)
from itda.authenticity.rubric import AXES, FACET_BY_KEY, FACET_KEYS
from itda.domain.canonical import canonical_sha256
from itda.domain.grounded_scoring import half_up


def _photo(
    source: SourceBundle,
    appearance_key: str,
) -> tuple[int | None, tuple[str, ...]]:
    images: dict[str, Evidence] = {}
    for record in source.evidence:
        observation = record.appearance
        if (
            record.modality != "IMAGE"
            or Claim.VISUAL_APPEARANCE not in allowed_claims(record)
            or observation is None
            or observation.key != appearance_key
            or observation.level is None
            or record.image_sha256 is None
        ):
            continue
        previous = images.get(record.image_sha256)
        if previous is not None:
            if previous.appearance != observation:
                raise ValueError("CONFLICTING_SAME_IMAGE_OBSERVATION")
            continue
        images[record.image_sha256] = record
    selected = tuple(images[k] for k in sorted(images))
    if not selected:
        return None, ()
    if len(selected) > 3:
        raise ValueError("PHOTO_REPRESENTATIVES_EXCEED_POLICY")
    levels = [
        e.appearance.level
        for e in selected
        if e.appearance is not None and e.appearance.level is not None
    ]
    return half_up(25 * sum(levels), len(levels)), tuple(sorted(e.evidence_id for e in selected))


def _social(
    source: SourceBundle,
    judgments: tuple[BoundJudgment, ...],
    policy: Policy,
) -> tuple[int | None, tuple[str, ...]]:
    records = [e for e in source.evidence if Claim.SOCIAL_CIRCULATION in allowed_claims(e)]
    if not records:
        return None, ()
    # One preregistered primary tag snapshot; never sum aliases or choose the largest.
    if len(records) != 1:
        raise ValueError("MULTIPLE_PRIMARY_TAG_COUNTS")
    record = records[0]
    if record.reported_count is None:
        return None, ()
    if policy.social_mode == "COUNT_AND_MEANING":
        social_ids = {
            e.evidence_id
            for e in source.evidence
            if e.receipt.provider == "APIFY_INSTAGRAM" and e.modality == "TEXT"
        }
        if not any(
            c.evidence_id in social_ids
            for j in judgments
            if j.key in {"E.a", "E.b"} and j.state == "SUPPORTED"
            for c in j.citations
        ):
            return None, ()
    bounded = min(record.reported_count, policy.social_log_ceiling)
    # This is a bounded circulation proxy, not visitor volume or authenticity truth.
    value = min(100, int(100 * math.log1p(bounded) / math.log1p(policy.social_log_ceiling) + 0.5))
    return value, (record.evidence_id,)


def score_facets(
    source: SourceBundle,
    judgments: tuple[BoundJudgment, ...],
    policy: Policy,
) -> tuple[FacetScore, ...]:
    if tuple(j.key for j in judgments) != FACET_KEYS:
        raise ValueError("FACET_MEMBERSHIP_INVALID")
    for judgment in judgments:
        verify_bound(judgment, source)
    scores = []
    for judgment in judgments:
        base = judgment.level * 25 if judgment.level is not None else None
        parts = []
        missing: list[str] = []
        if base is not None:
            parts.append(
                Contribution(
                    channel="TEXT",
                    value=base,
                    weight_bp=10000,
                    evidence_ids=tuple(sorted({c.evidence_id for c in judgment.citations})),
                    rule="ANCHORED_TEXT_LEVEL_0_TO_4",
                )
            )
        else:
            missing.append("TEXT")
        photo_key = {
            "E.c": "visual_character",
            "R.b": "natural_setting",
            "H.a": "traditional_appearance",
        }.get(judgment.key)
        photo_allowed = policy.photo_mode != "NONE" and judgment.key in {"E.c", "R.b"}
        if judgment.key == "H.a":
            photo_allowed = (
                policy.photo_mode == "HER_CONDITIONAL"
                and judgment.level is not None
                and judgment.level > 0
                and any(c.claim == Claim.HERITAGE_FACT for c in judgment.citations)
            )
        if photo_allowed and photo_key and policy.photo_share_bp > 0:
            appearance, ids = _photo(source, photo_key)
            if appearance is None:
                missing.append("PHOTO")
            else:
                share = policy.photo_share_bp if base is not None else 10000
                if parts:
                    parts[0] = parts[0].model_copy(update={"weight_bp": 10000 - share})
                parts.append(
                    Contribution(
                        channel="PHOTO",
                        value=appearance,
                        weight_bp=share,
                        evidence_ids=ids,
                        rule="VISUAL_CONTEXT_OF_TEXT_VERIFIED_HERITAGE"
                        if judgment.key == "H.a"
                        else "OBSERVED_APPEARANCE_ONLY",
                    )
                )
        if judgment.key == "E.b" and policy.social_mode != "NONE":
            circulation, ids = _social(source, judgments, policy)
            # Counts can supplement an established mediated meaning, not replace it.
            if base is None or circulation is None or policy.social_share_bp == 0:
                missing.append("SOCIAL")
            else:
                share = policy.social_share_bp
                parts[0] = parts[0].model_copy(update={"weight_bp": 10000 - share})
                parts.append(
                    Contribution(
                        channel="SOCIAL",
                        value=circulation,
                        weight_bp=share,
                        evidence_ids=ids,
                        rule="BOUNDED_PRIMARY_TAG_CIRCULATION_PROXY",
                    )
                )
        denominator = sum(p.weight_bp for p in parts)
        score = (
            half_up(sum(p.value * p.weight_bp for p in parts), denominator) if denominator else None
        )
        scores.append(
            FacetScore.model_validate(
                {
                    "key": judgment.key,
                    "value": score,
                    "contributions": [p.model_dump(mode="json") for p in parts],
                    "missing_channels": missing,
                    "reason": judgment.reason
                    if score is not None
                    else "이 항목을 판단할 허용된 근거가 없습니다.",
                }
            )
        )
    return tuple(scores)


def aggregate_axes(
    facets: tuple[FacetScore, ...],
    judgments: tuple[BoundJudgment, ...],
    policy: Policy,
) -> tuple[AxisScore, ...]:
    by_key = {j.key: j for j in judgments}
    axes = []
    for axis in AXES:
        rows = [f for f in facets if f.key.startswith(axis + ".")]
        supported = tuple(f.key for f in rows if f.value is not None)
        missing = tuple(f.key for f in rows if f.value is None)
        # H and E require a core textual meaning; pictures cannot establish an
        # original's authenticity or a socially shared meaning by themselves.
        core = any(
            FACET_BY_KEY[f.key].core
            and f.value is not None
            and (axis == "R" or by_key[f.key].state == "SUPPORTED")
            for f in rows
        )
        values = [f.value for f in rows if f.value is not None]
        sufficient = core and len(values) >= policy.minimum_facets
        axes.append(
            AxisScore(
                axis=axis,
                value=half_up(sum(values), len(values)) if sufficient else None,
                supported_facets=supported,
                missing_facets=missing,
                core_satisfied=core,
                reason=(
                    f"핵심 의미와 {len(values)}/4개 항목에 근거가 있어 집계했습니다."
                    if sufficient
                    else "축의 핵심 의미 또는 최소 항목 근거가 부족합니다."
                ),
            )
        )
    return tuple(axes)


def build_assessment(
    *,
    source: SourceBundle,
    judgments: tuple[BoundJudgment, ...],
    policy: Policy,
    rejections: tuple[Rejection, ...] = (),
    model_request_sha256: str | None = None,
    assessed_at: datetime,
) -> Assessment:
    SourceBundle.model_validate_json(source.model_dump_json())
    Policy.model_validate_json(policy.model_dump_json())
    facets = score_facets(source, judgments, policy)
    axes = aggregate_axes(facets, judgments, policy)
    payload = {
        "schema_version": "authenticity-assessment.v1",
        "source": source.model_dump(mode="json"),
        "policy": policy.model_dump(mode="json"),
        "judgments": [j.model_dump(mode="json") for j in judgments],
        "rejections": [r.model_dump(mode="json") for r in rejections],
        "facets": [f.model_dump(mode="json") for f in facets],
        "axes": [a.model_dump(mode="json") for a in axes],
        "model_request_sha256": model_request_sha256,
        "assessed_at": assessed_at.isoformat().replace("+00:00", "Z"),
    }
    return Assessment.model_validate(payload | {"assessment_sha256": canonical_sha256(payload)})


def verify_assessment(assessment: Assessment) -> None:
    parsed = Assessment.model_validate_json(assessment.model_dump_json())
    expected = build_assessment(
        source=parsed.source,
        judgments=parsed.judgments,
        policy=parsed.policy,
        rejections=parsed.rejections,
        model_request_sha256=parsed.model_request_sha256,
        assessed_at=parsed.assessed_at,
    )
    if expected != parsed:
        raise ValueError("ASSESSMENT_SCORE_TRACE_MISMATCH")
