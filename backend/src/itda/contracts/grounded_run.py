"""Independent supported-score recommendation receipt; no legacy item reinterpretation."""

from __future__ import annotations

from dataclasses import asdict
from datetime import date, datetime
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Score100, Sha256, StableId, StrictContract, require_utc
from itda.contracts.grounded_recommendation import GroundedFitTrace, GroundedTripInput
from itda.contracts.source_assessment import SourceEvidence, SupportState
from itda.domain.canonical import canonical_sha256

AXIS_KEYS = ("H", "E", "R")
TRAIT_KEYS = tuple(f"M{i}" for i in range(1, 7))
CONDITION_KEYS = (
    "VISIT_DATE_TIME",
    "COMPANIONS",
    "TRANSPORT",
    "WALKING",
    "INDOOR_OUTDOOR",
    "CROWD",
)


class GroundedPolicy(StrictContract):
    version: Literal["recommendation-kernel-v5"] = "recommendation-kernel-v5"
    minimum_supported_axes: Literal[2] = 2
    minimum_supported_subordinates: Literal[2] = 2
    experience_weight: Literal[8000] = 8000
    condition_weight: Literal[2000] = 2000
    mood_weight: Literal[1500] = 1500
    relevance_weight: Literal[8500] = 8500
    novelty_weight: Literal[1500] = 1500
    mismatch_axis_weight: Literal[6500] = 6500
    mismatch_trait_weight: Literal[3500] = 3500
    important_difference: Literal[70] = 70
    important_floor: Literal[50] = 50
    warning_confidence_min: Literal[65] = 65
    calibration: Literal["DEV_EVALUATION_REQUIRED"] = "DEV_EVALUATION_REQUIRED"

    @property
    def sha256(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))


GROUNDED_POLICY = GroundedPolicy()


class GroundedPreference(StrictContract):
    profile_id: StableId
    input_sha256: Sha256
    projection_version: Literal["grounded-preference-v1"] = "grounded-preference-v1"
    trip_input: GroundedTripInput
    purpose: Literal["SIGHTSEEING", "FOOD", "LODGING", "MIXED"]
    axis_targets: dict[str, Score100]
    trait_targets: dict[str, Score100 | None]
    important_traits: tuple[str, ...]
    condition_targets: dict[str, Score100 | None]
    mood_targets: dict[str, Score100 | None]
    photo_input_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_targets(self) -> Self:
        if (
            set(self.axis_targets) != set(AXIS_KEYS)
            or set(self.trait_targets) != set(TRAIT_KEYS)
            or set(self.condition_targets) != set(CONDITION_KEYS)
        ):
            raise ValueError("grounded preference dimensions must be explicit")
        if self.important_traits != tuple(sorted(set(self.important_traits))) or not set(
            self.important_traits
        ) <= set(TRAIT_KEYS):
            raise ValueError("important trait identities invalid")
        from itda.contracts.visual_mood import VisualMoodDimension

        if set(self.mood_targets) != {d.value for d in VisualMoodDimension}:
            raise ValueError("mood preference must use independent appearance vocabulary")
        if (
            any(v is not None for v in self.mood_targets.values())
            and self.photo_input_sha256 is None
        ):
            raise ValueError("mood preferences require a confirmed input identity")
        return self


class GroundedDimension(StrictContract):
    key: StableId
    value: Score100 | None
    state: SupportState
    evidence_ids: tuple[StableId, ...]
    reference_date: date | None
    reason: Annotated[str, Field(min_length=1, max_length=1000)]

    @model_validator(mode="after")
    def validate_dimension(self) -> Self:
        if self.state == SupportState.UNKNOWN:
            if self.value is not None:
                raise ValueError("unobserved display value must be null")
        elif self.value is None or self.reference_date is None or not self.evidence_ids:
            raise ValueError("supported display requires evidence and reference")
        if self.evidence_ids != tuple(sorted(set(self.evidence_ids))):
            raise ValueError("display evidence IDs must be canonical")
        return self


class GroundedMismatchTrace(StrictContract):
    axis_distance: Score100 | None
    trait_distance: Score100 | None
    raw_score: Score100 | None
    effective_score: Score100 | None
    compared_traits: tuple[str, ...]
    important_floor_applied: bool
    state: Literal[
        "INSUFFICIENT_EVIDENCE",
        "SUPPRESSED_LOW_CONFIDENCE",
        "NO_GUIDANCE",
        "GENTLE_DIFFERENCE",
        "MATERIAL_DIFFERENCE",
        "STRONG_DIFFERENCE",
    ]
    message_ko: str | None


class GroundedNoveltyPair(StrictContract):
    place_id: StableId
    shared_axes: tuple[str, ...]
    shared_traits: tuple[str, ...]
    score: Score100


class GroundedScoreTrace(StrictContract):
    experience: GroundedFitTrace
    conditions: GroundedFitTrace
    traits: GroundedFitTrace
    mood: GroundedFitTrace
    base_relevance: Score100
    effective_relevance: Score100
    mood_weight: Annotated[int, Field(strict=True, ge=0, le=1500)]
    novelty_pairs: tuple[GroundedNoveltyPair, ...]
    novelty_score: Score100
    rerank_numerator: Annotated[int, Field(strict=True, ge=0)]
    rerank_score: Score100

    @model_validator(mode="after")
    def validate_arithmetic(self) -> Self:
        from itda.domain.grounded_scoring import combine_groups, half_up

        base = combine_groups(((self.experience.score, 8000), (self.conditions.score, 2000)))
        if base is None or self.base_relevance != base:
            raise ValueError("base relevance arithmetic mismatch")
        mood_weight = 1500 if self.mood.score is not None else 0
        effective = combine_groups(((base, 10000 - mood_weight), (self.mood.score, mood_weight)))
        novelty = min((p.score for p in self.novelty_pairs), default=0)
        numerator = self.effective_relevance * 8500 + novelty * 1500
        if (
            self.mood_weight != mood_weight
            or self.effective_relevance != effective
            or self.novelty_score != novelty
            or self.rerank_numerator != numerator
            or self.rerank_score != half_up(numerator, 10000)
        ):
            raise ValueError("mood/diversity arithmetic mismatch")
        return self


class GroundedExplanation(StrictContract):
    dimension: Literal["H", "E", "R"]
    message_ko: Annotated[str, Field(min_length=1, max_length=200)]
    evidence_ids: tuple[StableId, ...]
    reference_date: date


class GroundedRecommendationItem(StrictContract):
    rank: Annotated[int, Field(strict=True, ge=1, le=5)]
    place_id: StableId
    place_name_ko: Annotated[str, Field(min_length=1, max_length=240)]
    region_code: Annotated[
        str | None, Field(pattern=r"^\d{5}$", exclude_if=lambda value: value is None)
    ] = None
    region_name: Annotated[
        str | None, Field(min_length=1, max_length=100, exclude_if=lambda value: value is None)
    ] = None
    address_ko: Annotated[
        str | None, Field(min_length=1, max_length=500, exclude_if=lambda value: value is None)
    ] = None
    raw_profile_sha256: Sha256
    assessment_bundle_sha256: Sha256
    fit_score: Score100
    overall_confidence: Score100 | None
    axis_scores: tuple[GroundedDimension, ...]
    mismatch_traits: tuple[GroundedDimension, ...]
    contribution: GroundedScoreTrace
    mismatch: GroundedMismatchTrace
    explanations: tuple[GroundedExplanation, ...]
    evidence: tuple[SourceEvidence, ...]
    supported_axes: Annotated[int, Field(strict=True, ge=0, le=3)]
    information_state: Literal["SUPPORTED", "LIMITED"]
    reference_date: date | None
    image_state: Literal["ABSENT"] = "ABSENT"

    @model_validator(mode="after")
    def validate_item(self) -> Self:
        if (
            tuple(a.key for a in self.axis_scores) != AXIS_KEYS
            or tuple(t.key for t in self.mismatch_traits) != TRAIT_KEYS
        ):
            raise ValueError("display dimensions must be canonical")
        supported = sum(a.value is not None for a in self.axis_scores)
        if self.supported_axes != supported or supported < 2:
            raise ValueError("candidate does not meet explicit axis support threshold")
        if self.fit_score != self.contribution.effective_relevance:
            raise ValueError("display fit differs from contribution")
        if self.information_state != ("SUPPORTED" if supported == 3 else "LIMITED"):
            raise ValueError("information state differs from support coverage")
        axes = {a.key: a.value for a in self.axis_scores}
        traits = {t.key: t.value for t in self.mismatch_traits}
        if axes != {c.key: c.actual for c in self.contribution.experience.components} or traits != {
            c.key: c.actual for c in self.contribution.traits.components
        }:
            raise ValueError("display values differ from compared observations")
        known = {e.evidence_id for e in self.evidence}
        for explanation in self.explanations:
            axis = next(a for a in self.axis_scores if a.key == explanation.dimension)
            if (
                axis.value is None
                or not set(explanation.evidence_ids) <= set(axis.evidence_ids)
                or not set(explanation.evidence_ids) <= known
            ):
                raise ValueError("explanation lacks supported dimension evidence")
        return self


class GroundedCandidateBinding(StrictContract):
    place_id: StableId
    raw_profile_sha256: Sha256
    assessment_bundle_sha256: Sha256


class GroundedAuthority(StrictContract):
    kernel_version: Literal["recommendation-kernel-v5"] = "recommendation-kernel-v5"
    config_sha256: Sha256
    release_sha256: Sha256
    source_release_sha256: Sha256
    assessment_manifest_sha256: Sha256
    candidate_sha256: Sha256
    membership_sha256: Sha256
    relation_sha256: Sha256
    candidate_assessment_sha256: Sha256
    contextual_snapshot_sha256: tuple[Sha256, ...]
    photo_input_sha256: Sha256 | None


class GroundedExclusion(StrictContract):
    place_id: StableId
    reason: Literal[
        "PURPOSE",
        "REGION",
        "INSUFFICIENT_SUPPORTED_AXES",
        "EXPLICIT_FACILITY_ABSENT",
        "SUPPORT_GATE",
    ]


class GroundedRecommendationRun(StrictContract):
    schema_version: Literal["itda.grounded-recommendation-run.v1"] = (
        "itda.grounded-recommendation-run.v1"
    )
    run_id: StableId
    input_digest: Sha256
    preference: GroundedPreference
    authority: GroundedAuthority
    candidate_bindings: tuple[GroundedCandidateBinding, ...]
    eligible_place_ids: tuple[StableId, ...]
    exclusions: tuple[GroundedExclusion, ...]
    items: Annotated[tuple[GroundedRecommendationItem, ...], Field(min_length=5, max_length=5)]
    created_at: datetime
    canonical_sha256: Sha256

    @property
    def candidate_place_ids(self) -> tuple[str, ...]:
        return tuple(c.place_id for c in self.candidate_bindings)

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        require_utc(self.created_at, field_name="created_at")
        ids = self.candidate_place_ids
        if (
            ids != tuple(sorted(set(ids)))
            or self.eligible_place_ids != tuple(sorted(set(self.eligible_place_ids)))
            or not set(self.eligible_place_ids) <= set(ids)
        ):
            raise ValueError("candidate membership must be canonical")
        if self.authority.config_sha256 != GROUNDED_POLICY.sha256:
            raise ValueError("unknown grounded scoring policy")
        if self.authority.candidate_assessment_sha256 != canonical_sha256(
            [r.model_dump(mode="json") for r in self.candidate_bindings]
        ):
            raise ValueError("candidate assessment binding mismatch")
        if (
            tuple(i.rank for i in self.items) != (1, 2, 3, 4, 5)
            or len({i.place_id for i in self.items}) != 5
        ):
            raise ValueError("grounded recommendation requires five unique ranked items")
        bound = {r.place_id: r for r in self.candidate_bindings}
        for index, item in enumerate(self.items):
            if self.preference.trip_input.region_code is not None and (
                item.region_code is None
                or not item.region_code.startswith(self.preference.trip_input.region_code)
            ):
                raise ValueError("ranked item is outside the selected region")
            if (
                item.place_id not in self.eligible_place_ids
                or item.raw_profile_sha256 != bound[item.place_id].raw_profile_sha256
                or item.assessment_bundle_sha256 != bound[item.place_id].assessment_bundle_sha256
            ):
                raise ValueError("ranked item source binding mismatch")
            for trace, targets in (
                (item.contribution.experience, self.preference.axis_targets),
                (item.contribution.traits, self.preference.trait_targets),
                (item.contribution.conditions, self.preference.condition_targets),
                (item.contribution.mood, self.preference.mood_targets),
            ):
                if {c.key: c.expected for c in trace.components} != targets:
                    raise ValueError("comparison targets differ from immutable preference")
                if any(c.weight != (1 if c.compared else 0) for c in trace.components):
                    raise ValueError("component weights differ from the frozen v5 policy")
            from itda.domain.grounded_scoring import mismatch

            expected_mismatch = mismatch(
                item.contribution.experience,
                item.contribution.traits,
                important_traits=frozenset(self.preference.important_traits),
                confidence=item.overall_confidence if item.overall_confidence is not None else 0,
            )
            if item.mismatch.model_dump(exclude={"message_ko"}) != asdict(expected_mismatch):
                raise ValueError("mismatch trace does not follow supported comparisons")
            expected_message = {
                "GENTLE_DIFFERENCE": "확인된 특성 중 기대와 조금 다른 부분이 있어요.",
                "MATERIAL_DIFFERENCE": "확인된 특성 중 기대와 다른 부분이 있어요.",
                "STRONG_DIFFERENCE": "기대와 다른 특성을 방문 전에 확인해 주세요.",
            }.get(expected_mismatch.state)
            if item.mismatch.message_ko != expected_message:
                raise ValueError("mismatch message exceeds validated guidance")
            if tuple(p.place_id for p in item.contribution.novelty_pairs) != tuple(
                p.place_id for p in self.items[:index]
            ):
                raise ValueError("novelty must compare every previously selected place")
            from itda.domain.grounded_scoring import pair_distance

            left = {d.key: d.value for d in (*item.axis_scores, *item.mismatch_traits)}
            for pair, prior in zip(
                item.contribution.novelty_pairs, self.items[:index], strict=True
            ):
                right = {d.key: d.value for d in (*prior.axis_scores, *prior.mismatch_traits)}
                shared_axes = tuple(
                    k for k in AXIS_KEYS if left[k] is not None and right[k] is not None
                )
                shared_traits = tuple(
                    k for k in TRAIT_KEYS if left[k] is not None and right[k] is not None
                )
                if (
                    pair.shared_axes != shared_axes
                    or pair.shared_traits != shared_traits
                    or pair.score != pair_distance(left, right)
                ):
                    raise ValueError("novelty trace differs from shared supported observations")
        if self.input_digest != canonical_sha256(
            {
                "preference": self.preference.model_dump(mode="json"),
                "authority": self.authority.model_dump(mode="json"),
            }
        ):
            raise ValueError("grounded input digest mismatch")
        digest = canonical_sha256(
            self.model_dump(mode="json", exclude={"created_at", "canonical_sha256", "run_id"})
        )
        if self.canonical_sha256 != digest or self.run_id != f"recommendation-run:{digest[:32]}":
            raise ValueError("grounded receipt digest mismatch")
        return self
