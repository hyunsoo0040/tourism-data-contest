"""Provider-free Phase 4 benchmark, review, and adoption contracts."""

from __future__ import annotations

import hashlib
import hmac
import math
import statistics
from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Protocol, Self

from pydantic import Field, StrictBool, field_validator, model_validator

from itda.contracts.base import Sha256, StableId, StrictContract, Version, require_utc
from itda.contracts.catalog_optional_media import ImageMediumState
from itda.contracts.profile_fusion import CANONICAL_FUSION_POLICY
from itda.domain.canonical import canonical_sha256

_FORBIDDEN_EVALUATOR_KEY_PARTS = (
    "blind",
    "complement",
    "image_bytes",
    "image_path",
    "provider_credential",
    "provider_request_capability",
    "raw_image",
    "raw_provider",
    "release_authority",
    "release_token",
)


def _utc_text(value: datetime) -> str:
    return require_utc(value, field_name="timestamp").isoformat().replace("+00:00", "Z")


def _reject_forbidden_evaluator_input(value: object) -> None:
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, Mapping):
            for key, nested in current.items():
                folded = str(key).casefold()
                if any(part in folded for part in _FORBIDDEN_EVALUATOR_KEY_PARTS):
                    raise ValueError("benchmark accepts digest-only evaluator authority")
                stack.append(nested)
        elif isinstance(current, (list, tuple)):
            stack.extend(current)
        elif isinstance(current, (bytes, bytearray, memoryview)):
            raise ValueError("benchmark accepts digest-only evaluator authority")


def _require_self_digest(model: StrictContract, field_name: str) -> None:
    actual = getattr(model, field_name)
    expected = canonical_sha256(model.model_dump(mode="json", exclude={field_name}))
    if not hmac.compare_digest(actual, expected):
        raise ValueError(f"{field_name} digest drifted")


class ReviewVerdict(StrEnum):
    SUPPORTED = "SUPPORTED"
    NON_VISIBLE = "NON_VISIBLE"
    PHANTOM_REF = "PHANTOM_REF"
    UNSUPPORTED = "UNSUPPORTED"


class _SelectionBinding(Protocol):
    batch_sha256: str


class _PredictionBinding(Protocol):
    selection_manifest_sha256: str
    batch_sha256: str
    frozen_at: datetime


class _FreezeBinding(Protocol):
    prediction_batch_sha256: str
    selection_manifest_sha256: str
    dev_case_inventory: tuple[str, ...] | None
    dev_case_inventory_sha256: str | None
    frozen_at: datetime
    receipt_sha256: str


class _LabelCapabilityBinding(Protocol):
    prediction_batch_sha256: str
    prediction_freeze_receipt_sha256: str
    prediction_dev_case_inventory: tuple[str, ...]
    prediction_dev_case_inventory_sha256: str
    label_case_inventory_sha256: str
    prediction_case_records_sha256: str
    label_case_records_sha256: str
    review_inventory_sha256: str
    capability_sha256: str
    evaluator_authority_sha256: str
    created_at: datetime


class BenchmarkAuthorityBinding(StrictContract):
    """Exact prediction-freeze and later label-capability join."""

    schema_version: str
    dev_authority_sha256: Sha256
    selection_manifest_sha256: Sha256
    prediction_batch_sha256: Sha256
    prediction_freeze_receipt_sha256: Sha256
    dev_case_inventory_sha256: Sha256
    label_case_inventory_sha256: Sha256
    prediction_case_records_sha256: Sha256
    label_case_records_sha256: Sha256
    review_inventory_sha256: Sha256
    label_capability_sha256: Sha256
    evaluator_authority_sha256: Sha256
    prediction_frozen_at: datetime
    label_capability_created_at: datetime
    authority_binding_sha256: Sha256

    @model_validator(mode="before")
    @classmethod
    def reject_escalated_capabilities(cls, value: object) -> object:
        _reject_forbidden_evaluator_input(value)
        return value

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, value: str) -> str:
        if value != "itda.phase4-benchmark-authority.v2":
            raise ValueError("benchmark authority schema is not supported")
        return value

    @field_validator("prediction_frozen_at", "label_capability_created_at")
    @classmethod
    def validate_timestamp(cls, value: datetime, info: object) -> datetime:
        return require_utc(value, field_name=getattr(info, "field_name", "timestamp"))

    @model_validator(mode="after")
    def validate_freeze_before_label(self) -> Self:
        if self.label_capability_created_at < self.prediction_frozen_at:
            raise ValueError("label capability cannot precede prediction freeze")
        _require_self_digest(self, "authority_binding_sha256")
        return self

    @classmethod
    def build(
        cls,
        *,
        dev_authority_sha256: str,
        selection_manifest_sha256: str,
        prediction_batch_sha256: str,
        prediction_freeze_receipt_sha256: str,
        dev_case_inventory_sha256: str,
        label_case_inventory_sha256: str,
        prediction_case_records_sha256: str,
        label_case_records_sha256: str,
        review_inventory_sha256: str,
        label_capability_sha256: str,
        evaluator_authority_sha256: str,
        prediction_frozen_at: datetime,
        label_capability_created_at: datetime,
    ) -> BenchmarkAuthorityBinding:
        fields: dict[str, object] = {
            "schema_version": "itda.phase4-benchmark-authority.v2",
            "dev_authority_sha256": dev_authority_sha256,
            "selection_manifest_sha256": selection_manifest_sha256,
            "prediction_batch_sha256": prediction_batch_sha256,
            "prediction_freeze_receipt_sha256": prediction_freeze_receipt_sha256,
            "dev_case_inventory_sha256": dev_case_inventory_sha256,
            "label_case_inventory_sha256": label_case_inventory_sha256,
            "prediction_case_records_sha256": prediction_case_records_sha256,
            "label_case_records_sha256": label_case_records_sha256,
            "review_inventory_sha256": review_inventory_sha256,
            "label_capability_sha256": label_capability_sha256,
            "evaluator_authority_sha256": evaluator_authority_sha256,
            "prediction_frozen_at": _utc_text(prediction_frozen_at),
            "label_capability_created_at": _utc_text(label_capability_created_at),
        }
        return cls.model_validate({**fields, "authority_binding_sha256": canonical_sha256(fields)})


def bind_evaluator_authority(
    *,
    dev_authority_sha256: str,
    selection: _SelectionBinding,
    predictions: _PredictionBinding,
    freeze_receipt: _FreezeBinding,
    label_capability: _LabelCapabilityBinding,
) -> BenchmarkAuthorityBinding:
    """Join validated upstream digests without importing provider code."""

    selection_sha256 = selection.batch_sha256
    prediction_selection_sha256 = predictions.selection_manifest_sha256
    prediction_batch_sha256 = predictions.batch_sha256
    prediction_frozen_at = predictions.frozen_at
    if selection_sha256 != prediction_selection_sha256:
        raise ValueError("selection manifest does not match frozen predictions")
    if (
        freeze_receipt.prediction_batch_sha256 != prediction_batch_sha256
        or freeze_receipt.selection_manifest_sha256 != selection_sha256
        or freeze_receipt.frozen_at != prediction_frozen_at
    ):
        raise ValueError("prediction freeze receipt does not resolve the frozen batch")
    if (
        label_capability.prediction_batch_sha256 != prediction_batch_sha256
        or label_capability.prediction_freeze_receipt_sha256 != freeze_receipt.receipt_sha256
    ):
        raise ValueError("label capability does not resolve the prediction freeze")
    inventory = freeze_receipt.dev_case_inventory
    inventory_sha256 = freeze_receipt.dev_case_inventory_sha256
    if inventory is None or inventory_sha256 is None:
        raise ValueError("prediction freeze receipt lacks a protected DEV case inventory")
    expected_inventory_sha256 = canonical_sha256(list(inventory))
    if (
        len(set(inventory)) != len(inventory)
        or tuple(sorted(inventory)) != inventory
        or inventory_sha256 != expected_inventory_sha256
        or label_capability.prediction_dev_case_inventory != inventory
        or label_capability.prediction_dev_case_inventory_sha256 != expected_inventory_sha256
        or label_capability.label_case_inventory_sha256 != expected_inventory_sha256
    ):
        raise ValueError("prediction freeze and label capability DEV case inventories drifted")
    return BenchmarkAuthorityBinding.build(
        dev_authority_sha256=dev_authority_sha256,
        selection_manifest_sha256=selection_sha256,
        prediction_batch_sha256=prediction_batch_sha256,
        prediction_freeze_receipt_sha256=freeze_receipt.receipt_sha256,
        dev_case_inventory_sha256=expected_inventory_sha256,
        label_case_inventory_sha256=label_capability.label_case_inventory_sha256,
        prediction_case_records_sha256=label_capability.prediction_case_records_sha256,
        label_case_records_sha256=label_capability.label_case_records_sha256,
        review_inventory_sha256=label_capability.review_inventory_sha256,
        label_capability_sha256=label_capability.capability_sha256,
        evaluator_authority_sha256=label_capability.evaluator_authority_sha256,
        prediction_frozen_at=prediction_frozen_at,
        label_capability_created_at=label_capability.created_at,
    )


class HumanReviewInventoryItem(StrictContract):
    stable_observation_id: StableId
    claim_id: StableId
    evidence_ref_id: StableId
    representative_id: StableId
    region_caption_sha256: Sha256
    critical: bool
    prediction_batch_sha256: Sha256
    selection_manifest_sha256: Sha256
    inventory_item_sha256: Sha256

    @classmethod
    def build(
        cls,
        *,
        stable_observation_id: str,
        claim_id: str,
        evidence_ref_id: str,
        representative_id: str,
        region_caption_sha256: str,
        critical: bool,
        prediction_batch_sha256: str,
        selection_manifest_sha256: str,
    ) -> HumanReviewInventoryItem:
        fields: dict[str, object] = {
            "stable_observation_id": stable_observation_id,
            "claim_id": claim_id,
            "evidence_ref_id": evidence_ref_id,
            "representative_id": representative_id,
            "region_caption_sha256": region_caption_sha256,
            "critical": critical,
            "prediction_batch_sha256": prediction_batch_sha256,
            "selection_manifest_sha256": selection_manifest_sha256,
        }
        return cls.model_validate({**fields, "inventory_item_sha256": canonical_sha256(fields)})

    @model_validator(mode="after")
    def validate_digest(self) -> Self:
        _require_self_digest(self, "inventory_item_sha256")
        return self


class HumanVisibleEvidenceReviewEntry(StrictContract):
    inventory_item_sha256: Sha256
    verdict: ReviewVerdict
    notes_sha256: Sha256


class HumanVisibleEvidenceReviewManifest(StrictContract):
    schema_version: str
    prediction_batch_sha256: Sha256
    provisional_report_sha256: Sha256
    selection_manifest_sha256: Sha256
    expected_inventory: Annotated[tuple[HumanReviewInventoryItem, ...], Field(min_length=1)]
    expected_inventory_sha256: Sha256
    entries: Annotated[tuple[HumanVisibleEvidenceReviewEntry, ...], Field(min_length=1)]
    reviewer_pseudonym: Annotated[str, Field(strict=True, min_length=3, max_length=100)]
    completed_at: datetime
    review_manifest_sha256: Sha256

    @model_validator(mode="before")
    @classmethod
    def reject_protected_material(cls, value: object) -> object:
        _reject_forbidden_evaluator_input(value)
        return value

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, value: str) -> str:
        if value != "itda.phase4-human-visible-review.v1":
            raise ValueError("human visible review schema is not supported")
        return value

    @field_validator("completed_at")
    @classmethod
    def validate_completed_at(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="completed_at")

    @model_validator(mode="after")
    def validate_complete_review(self) -> Self:
        inventory_ids = tuple(item.inventory_item_sha256 for item in self.expected_inventory)
        entry_ids = tuple(entry.inventory_item_sha256 for entry in self.entries)
        if inventory_ids != tuple(sorted(inventory_ids)) or len(set(inventory_ids)) != len(
            inventory_ids
        ):
            raise ValueError("review inventory must be unique and canonical")
        if entry_ids != inventory_ids:
            raise ValueError("review entries must equal the complete expected inventory")
        expected_inventory_digest = canonical_sha256(
            [item.model_dump(mode="json") for item in self.expected_inventory]
        )
        if not hmac.compare_digest(self.expected_inventory_sha256, expected_inventory_digest):
            raise ValueError("expected review inventory digest drifted")
        if any(
            item.prediction_batch_sha256 != self.prediction_batch_sha256
            or item.selection_manifest_sha256 != self.selection_manifest_sha256
            for item in self.expected_inventory
        ):
            raise ValueError("review inventory lineage does not match the reviewed artifacts")
        _require_self_digest(self, "review_manifest_sha256")
        return self

    @classmethod
    def build(
        cls,
        *,
        prediction_batch_sha256: str,
        provisional_report_sha256: str,
        selection_manifest_sha256: str,
        expected_inventory: tuple[HumanReviewInventoryItem, ...],
        entries: tuple[HumanVisibleEvidenceReviewEntry, ...],
        reviewer_pseudonym: str,
        completed_at: datetime,
    ) -> HumanVisibleEvidenceReviewManifest:
        ordered_inventory = tuple(
            sorted(expected_inventory, key=lambda item: item.inventory_item_sha256)
        )
        entries_by_id = {entry.inventory_item_sha256: entry for entry in entries}
        if len(entries_by_id) != len(entries) or set(entries_by_id) != {
            item.inventory_item_sha256 for item in ordered_inventory
        }:
            raise ValueError("review entries must equal the complete expected inventory")
        ordered_entries = tuple(
            entries_by_id[item.inventory_item_sha256] for item in ordered_inventory
        )
        inventory_payload = [item.model_dump(mode="json") for item in ordered_inventory]
        fields: dict[str, object] = {
            "schema_version": "itda.phase4-human-visible-review.v1",
            "prediction_batch_sha256": prediction_batch_sha256,
            "provisional_report_sha256": provisional_report_sha256,
            "selection_manifest_sha256": selection_manifest_sha256,
            "expected_inventory": inventory_payload,
            "expected_inventory_sha256": canonical_sha256(inventory_payload),
            "entries": [entry.model_dump(mode="json") for entry in ordered_entries],
            "reviewer_pseudonym": reviewer_pseudonym,
            "completed_at": _utc_text(completed_at),
        }
        return cls.model_validate({**fields, "review_manifest_sha256": canonical_sha256(fields)})


AttributeId = Literal["H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "R1", "R2", "R3", "R4"]
AxisId = Literal["H", "E", "R"]
ATTRIBUTE_IDS: tuple[AttributeId, ...] = (
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
_AXIS_ATTRIBUTES: dict[AxisId, tuple[AttributeId, ...]] = {
    "H": ATTRIBUTE_IDS[0:4],
    "E": ATTRIBUTE_IDS[4:8],
    "R": ATTRIBUTE_IDS[8:12],
}


class BenchmarkReportState(StrEnum):
    PROVISIONAL_PENDING_HUMAN_REVIEW = "PROVISIONAL_PENDING_HUMAN_REVIEW"
    PENDING_EXTERNAL_EVIDENCE = "PENDING_EXTERNAL_EVIDENCE"
    ADOPT = "ADOPT"
    CONDITIONAL_ADOPT = "CONDITIONAL_ADOPT"
    REJECT = "REJECT"
    IMAGE_REJECTED_TEXT_ODII_ONLY = "IMAGE_REJECTED_TEXT_ODII_ONLY"
    NO_IMAGE_TEXT_ODII_ONLY = "NO_IMAGE_TEXT_ODII_ONLY"
    SYNTHETIC_EVALUATION_ONLY = "SYNTHETIC_EVALUATION_ONLY"


class AttributeScore(StrictContract):
    attribute_id: AttributeId
    score_milli: Annotated[int, Field(strict=True, ge=0, le=4_000)] | None


class BenchmarkScoreVector(StrictContract):
    values: Annotated[tuple[AttributeScore, ...], Field(min_length=12, max_length=12)]

    @classmethod
    def from_mapping(cls, values: Mapping[str, int | None]) -> BenchmarkScoreVector:
        if tuple(values) != ATTRIBUTE_IDS:
            raise ValueError("benchmark scores require canonical H1-R4 order")
        return cls(
            values=tuple(
                AttributeScore(attribute_id=attribute_id, score_milli=values[attribute_id])
                for attribute_id in ATTRIBUTE_IDS
            )
        )

    @model_validator(mode="after")
    def validate_order(self) -> Self:
        if tuple(value.attribute_id for value in self.values) != ATTRIBUTE_IDS:
            raise ValueError("benchmark scores require canonical H1-R4 order")
        return self

    def as_mapping(self) -> dict[str, int | None]:
        return {value.attribute_id: value.score_milli for value in self.values}


class BenchmarkRepeat(StrictContract):
    repeat_index: Literal[1, 2, 3]
    request_identity_sha256: Sha256
    prediction_batch_sha256: Sha256
    terminal_status: Annotated[str, Field(strict=True, min_length=1, max_length=80)]
    schema_compliant: StrictBool
    scores: BenchmarkScoreVector
    raw_prediction_ref: Sha256 | None
    execution_receipt_sha256: Sha256

    @model_validator(mode="after")
    def validate_execution_receipt(self) -> Self:
        _require_self_digest(self, "execution_receipt_sha256")
        return self

    @classmethod
    def build(cls, **values: object) -> BenchmarkRepeat:
        payload = {
            key: value.model_dump(mode="json") if isinstance(value, StrictContract) else value
            for key, value in values.items()
        }
        return cls.model_validate({**values, "execution_receipt_sha256": canonical_sha256(payload)})


class BenchmarkCase(StrictContract):
    case_ref: StableId
    image_medium_state: ImageMediumState
    baseline_scores: BenchmarkScoreVector
    candidate_repeats: Annotated[tuple[BenchmarkRepeat, ...], Field(min_length=3, max_length=3)]
    dev_label_scores: BenchmarkScoreVector
    baseline_display_label: StableId
    candidate_display_label: StableId
    dev_display_label: StableId
    confidence_percent: Annotated[int, Field(strict=True, ge=0, le=100)]
    visible_claim_count: Annotated[int, Field(strict=True, ge=0)]
    automatic_supported_claim_count: Annotated[int, Field(strict=True, ge=0)]
    named_failures: tuple[Annotated[str, Field(strict=True, min_length=1, max_length=160)], ...]

    @model_validator(mode="after")
    def validate_case(self) -> Self:
        if self.automatic_supported_claim_count > self.visible_claim_count:
            raise ValueError("supported visible claim count cannot exceed its denominator")
        if tuple(repeat.repeat_index for repeat in self.candidate_repeats) != (1, 2, 3):
            raise ValueError("benchmark repeats require exact ordered repeat indexes 1-3")
        execution_receipts = tuple(
            repeat.execution_receipt_sha256 for repeat in self.candidate_repeats
        )
        if len(set(execution_receipts)) != 3:
            raise ValueError("benchmark repeats require three distinct execution receipts")
        request_identities = tuple(
            repeat.request_identity_sha256 for repeat in self.candidate_repeats
        )
        if len(set(request_identities)) != 3:
            raise ValueError("benchmark repeats require three distinct request identities")
        has_candidate_scores = any(
            score is not None
            for repeat in self.candidate_repeats
            for score in repeat.scores.as_mapping().values()
        )
        raw_prediction_refs = tuple(
            repeat.raw_prediction_ref for repeat in self.candidate_repeats
        )
        if self.image_medium_state is ImageMediumState.QUALIFIED and has_candidate_scores and (
            any(ref is None for ref in raw_prediction_refs)
            or len(set(raw_prediction_refs)) != 3
        ):
            raise ValueError(
                "qualified benchmark repeats require three distinct upstream prediction artifacts"
            )
        if self.image_medium_state is not ImageMediumState.QUALIFIED:
            if any(
                score is not None
                for repeat in self.candidate_repeats
                for score in repeat.scores.as_mapping().values()
            ):
                raise ValueError("non-image benchmark case cannot carry candidate scores")
            if any(repeat.raw_prediction_ref is not None for repeat in self.candidate_repeats):
                raise ValueError("non-image benchmark case cannot carry image artifact refs")
            if self.visible_claim_count != 0 or self.automatic_supported_claim_count != 0:
                raise ValueError("non-image benchmark case cannot carry image claims")
            if self.candidate_display_label != self.baseline_display_label:
                raise ValueError("non-image benchmark case must inherit the baseline display label")
        return self


class BenchmarkExperiment(StrictContract):
    schema_version: Literal["itda.phase4-benchmark-experiment.v2"]
    experiment_id: StableId
    evaluation_scope: Literal["DEV_24_PROTECTED", "SYNTHETIC_PROVIDER_FREE"]
    dev_authority_sha256: Sha256
    authority_binding_sha256: Sha256
    prompt_config_sha256: Sha256
    prompt_language: Literal["KOREAN", "BILINGUAL"]
    prompt_routing: Literal["GLOBAL", "ATTRIBUTE_PREDECLARED"]
    selection_manifest_sha256: Sha256
    selection_policy_sha256: Sha256
    fusion_policy_sha256: Sha256
    threshold_config_sha256: Sha256
    seed: Annotated[int, Field(strict=True, ge=0)]
    code_sha256: Sha256
    baseline_sha256: Sha256
    prediction_batch_sha256: Sha256
    dev_case_inventory_sha256: Sha256
    label_case_inventory_sha256: Sha256
    prediction_case_records_sha256: Sha256
    label_case_records_sha256: Sha256
    review_inventory_sha256: Sha256
    label_version: Version
    predeclared_conditional_attributes: tuple[
        Literal["H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "R1", "R2", "R3", "R4"], ...
    ]
    created_at: datetime
    experiment_sha256: Sha256

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="created_at")

    @model_validator(mode="after")
    def validate_experiment(self) -> Self:
        if self.fusion_policy_sha256 != CANONICAL_FUSION_POLICY.policy_sha256:
            raise ValueError("release experiment must bind the exact canonical fusion policy")
        if len(set(self.predeclared_conditional_attributes)) != len(
            self.predeclared_conditional_attributes
        ):
            raise ValueError("conditional attributes must be predeclared once")
        _require_self_digest(self, "experiment_sha256")
        return self

    @classmethod
    def build(cls, **values: object) -> BenchmarkExperiment:
        fields = {
            "schema_version": "itda.phase4-benchmark-experiment.v2",
            **values,
        }
        created_at = fields.get("created_at")
        if isinstance(created_at, datetime):
            fields["created_at"] = _utc_text(created_at)
        return cls.model_validate({**fields, "experiment_sha256": canonical_sha256(fields)})


class MetricValue(StrictContract):
    value: float | None
    numerator: Annotated[int, Field(strict=True, ge=0)]
    denominator: Annotated[int, Field(strict=True, ge=0)]
    undefined_reason: Annotated[str, Field(strict=True, min_length=1, max_length=160)] | None = None

    @model_validator(mode="after")
    def validate_defined_state(self) -> Self:
        if self.denominator == 0:
            if self.value is not None or self.undefined_reason is None:
                raise ValueError("undefined metric requires a named reason")
        elif self.value is None or self.undefined_reason is not None:
            raise ValueError("defined metric cannot carry an undefined reason")
        return self


class CoverageByState(StrictContract):
    image_medium_state: ImageMediumState
    total_count: Annotated[int, Field(strict=True, ge=0)]
    usable_count: Annotated[int, Field(strict=True, ge=0)]


class BenchmarkCoverage(StrictContract):
    total_count: Annotated[int, Field(strict=True, ge=1)]
    usable_count: Annotated[int, Field(strict=True, ge=0)]
    by_state: Annotated[tuple[CoverageByState, ...], Field(min_length=6, max_length=6)]

    @model_validator(mode="after")
    def validate_coverage(self) -> Self:
        if tuple(row.image_medium_state for row in self.by_state) != tuple(ImageMediumState):
            raise ValueError("coverage requires the exact image-state denominator vocabulary")
        if sum(row.total_count for row in self.by_state) != self.total_count:
            raise ValueError("coverage state denominators do not sum to the cohort")
        if sum(row.usable_count for row in self.by_state) != self.usable_count:
            raise ValueError("coverage usable counts do not sum to the cohort")
        return self


class AxisMetric(StrictContract):
    axis_id: AxisId
    baseline_mae: MetricValue
    candidate_mae: MetricValue
    candidate_degradation_points: float | None


class AttributeMetric(StrictContract):
    attribute_id: AttributeId
    baseline_mae: MetricValue
    candidate_mae: MetricValue
    improvement: MetricValue


class BootstrapInterval(StrictContract):
    confidence_bp: Literal[9500]
    seed: Annotated[int, Field(strict=True, ge=0)]
    resample_count: Literal[2000]
    eligible_inventory_sha256: Sha256
    eligible_count: Annotated[int, Field(strict=True, ge=0)]
    estimate: float | None
    lower: float | None
    upper: float | None
    undefined_reason: Annotated[str, Field(strict=True, min_length=1, max_length=160)] | None

    @model_validator(mode="after")
    def validate_defined_state(self) -> Self:
        values = (self.estimate, self.lower, self.upper)
        if self.eligible_count == 0:
            if any(value is not None for value in values) or self.undefined_reason is None:
                raise ValueError("empty bootstrap interval requires a named reason")
        elif any(value is None for value in values) or self.undefined_reason is not None:
            raise ValueError("defined bootstrap interval cannot carry an undefined reason")
        elif self.lower is not None and self.upper is not None and self.lower > self.upper:
            raise ValueError("bootstrap interval bounds are reversed")
        return self


class BenchmarkMetrics(StrictContract):
    repeat_count: Literal[3]
    schema_compliance: MetricValue
    terminal_observability_agreement: MetricValue
    median_raw_score_difference: MetricValue
    coverage: BenchmarkCoverage
    baseline_candidate_attribute_agreement: MetricValue
    candidate_dev_label_agreement: MetricValue
    automatic_visible_support_precision: MetricValue
    baseline_attribute_mae: MetricValue
    candidate_attribute_mae: MetricValue
    macro_attribute_mae_improvement: MetricValue
    macro_attribute_mae_improvement_ci95: BootstrapInterval
    attribute_metrics: Annotated[tuple[AttributeMetric, ...], Field(min_length=12, max_length=12)]
    axis_metrics: tuple[AxisMetric, AxisMetric, AxisMetric]
    baseline_spearman: MetricValue
    candidate_spearman: MetricValue
    baseline_macro_f1: MetricValue
    candidate_macro_f1: MetricValue
    missing_attribute_count: Annotated[int, Field(strict=True, ge=0)]
    named_failures: tuple[str, ...]
    candidate_rank_scores: tuple[tuple[StableId, int], ...]
    confidence_is_ranking_input: Literal[False]
    stability_gates_pass: StrictBool
    noninferiority_gates_pass: StrictBool
    global_value_gates_pass: StrictBool


class SensitivityEvidence(StrictContract):
    section: Literal["SENSITIVITY_ONLY"]
    config_sha256: Sha256
    changed_dimensions: Annotated[tuple[str, ...], Field(min_length=1)]
    release_eligible: StrictBool

    @model_validator(mode="after")
    def reject_release_eligibility(self) -> Self:
        if self.release_eligible:
            raise ValueError("sensitivity evidence can never be release eligible")
        return self


class ProvisionalBenchmarkReport(StrictContract):
    schema_version: Literal["itda.phase4-provisional-benchmark.v1"]
    state: Literal[BenchmarkReportState.PROVISIONAL_PENDING_HUMAN_REVIEW]
    experiment: BenchmarkExperiment
    cases: Annotated[tuple[BenchmarkCase, ...], Field(min_length=1)]
    metrics: BenchmarkMetrics
    review_inventory: tuple[HumanReviewInventoryItem, ...]
    sensitivity: tuple[SensitivityEvidence, ...]
    raw_prediction_refs: tuple[Sha256, ...]
    generated_at: datetime
    provisional_report_sha256: Sha256

    @field_validator("generated_at")
    @classmethod
    def validate_generated_at(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="generated_at")

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        if any(
            item.prediction_batch_sha256 != self.experiment.prediction_batch_sha256
            or item.selection_manifest_sha256 != self.experiment.selection_manifest_sha256
            for item in self.review_inventory
        ):
            raise ValueError("review inventory does not bind the experiment lineage")
        _require_self_digest(self, "provisional_report_sha256")
        return self


class ZeroImageFallbackProof(StrictContract):
    schema_version: Literal["itda.phase4-zero-image-fallback.v1"]
    outcome: Literal[
        BenchmarkReportState.IMAGE_REJECTED_TEXT_ODII_ONLY,
        BenchmarkReportState.NO_IMAGE_TEXT_ODII_ONLY,
    ]
    source_media_state: ImageMediumState
    image_value_count: Literal[0]
    image_weight_bp: Literal[0]
    image_contribution_milli: Literal[0]
    image_claim_count: Literal[0]
    image_ref_count: Literal[0]
    provisional_report_sha256: Sha256
    baseline_sha256: Sha256
    fallback_lineage_sha256: Sha256
    proof_sha256: Sha256

    @model_validator(mode="after")
    def validate_fallback(self) -> Self:
        no_image_states = {
            ImageMediumState.MISSING,
            ImageMediumState.EMPTY,
            ImageMediumState.PROVENANCE_INCOMPLETE,
            ImageMediumState.RIGHTS_RESTRICTED,
        }
        if (
            self.outcome is BenchmarkReportState.NO_IMAGE_TEXT_ODII_ONLY
            and self.source_media_state not in no_image_states
        ):
            raise ValueError("no-image fallback requires explicit non-image lineage")
        if (
            self.outcome is BenchmarkReportState.IMAGE_REJECTED_TEXT_ODII_ONLY
            and self.source_media_state
            not in {ImageMediumState.QUALIFIED, ImageMediumState.ANALYSIS_FAILED}
        ):
            raise ValueError("image-rejected fallback requires rejected image lineage")
        _require_self_digest(self, "proof_sha256")
        return self

    @classmethod
    def build(
        cls,
        *,
        outcome: BenchmarkReportState,
        source_media_state: ImageMediumState,
        provisional_report_sha256: str,
        baseline_sha256: str,
    ) -> ZeroImageFallbackProof:
        fields: dict[str, object] = {
            "schema_version": "itda.phase4-zero-image-fallback.v1",
            "outcome": outcome,
            "source_media_state": source_media_state,
            "image_value_count": 0,
            "image_weight_bp": 0,
            "image_contribution_milli": 0,
            "image_claim_count": 0,
            "image_ref_count": 0,
            "provisional_report_sha256": provisional_report_sha256,
            "baseline_sha256": baseline_sha256,
            "fallback_lineage_sha256": canonical_sha256(
                {
                    "provisional_report_sha256": provisional_report_sha256,
                    "baseline_sha256": baseline_sha256,
                }
            ),
        }
        return cls.model_validate({**fields, "proof_sha256": canonical_sha256(fields)})


class BenchmarkDecisionReport(StrictContract):
    schema_version: Literal["itda.phase4-benchmark-decision.v1"]
    state: BenchmarkReportState
    evaluation_scope: Literal["DEV_24_PROTECTED", "SYNTHETIC_PROVIDER_FREE"]
    dev_authority_sha256: Sha256
    provisional_report_sha256: Sha256
    selected_config_sha256: Sha256
    locked_fusion_policy_sha256: Sha256
    human_review_manifest_sha256: Sha256 | None
    zero_image_fallback_sha256: Sha256 | None
    visible_support_precision: MetricValue
    adopted_attributes: tuple[
        Literal["H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "R1", "R2", "R3", "R4"], ...
    ]
    inherited_baseline_attributes: tuple[
        Literal["H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "R1", "R2", "R3", "R4"], ...
    ]
    failures: tuple[str, ...]
    reason: Annotated[str, Field(strict=True, min_length=1, max_length=240)]
    raw_artifact_refs: tuple[Sha256, ...]
    image_contribution_count: Annotated[int, Field(strict=True, ge=0)]
    finalized_at: datetime
    final_report_sha256: Sha256

    @field_validator("finalized_at")
    @classmethod
    def validate_finalized_at(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="finalized_at")

    @model_validator(mode="after")
    def validate_decision(self) -> Self:
        if self.locked_fusion_policy_sha256 != CANONICAL_FUSION_POLICY.policy_sha256:
            raise ValueError("terminal decision must bind the canonical fusion policy")
        if self.state is BenchmarkReportState.ADOPT and self.adopted_attributes != ATTRIBUTE_IDS:
            raise ValueError("global adoption must adopt the complete H1-R4 inventory")
        if self.state is BenchmarkReportState.CONDITIONAL_ADOPT and not self.adopted_attributes:
            raise ValueError("conditional adoption requires predeclared adopted attributes")
        if self.evaluation_scope != "DEV_24_PROTECTED" and self.state in {
            BenchmarkReportState.ADOPT,
            BenchmarkReportState.CONDITIONAL_ADOPT,
        }:
            raise ValueError("synthetic evidence cannot emit a release adoption decision")
        if self.state is BenchmarkReportState.SYNTHETIC_EVALUATION_ONLY and (
            self.evaluation_scope != "SYNTHETIC_PROVIDER_FREE" or self.adopted_attributes
        ):
            raise ValueError("synthetic terminal state cannot carry release authority")
        if self.state in {
            BenchmarkReportState.IMAGE_REJECTED_TEXT_ODII_ONLY,
            BenchmarkReportState.NO_IMAGE_TEXT_ODII_ONLY,
        } and (
            self.image_contribution_count != 0
            or self.adopted_attributes
            or self.zero_image_fallback_sha256 is None
            or self.raw_artifact_refs
        ):
            raise ValueError("zero-image terminal paths cannot contain image authority")
        _require_self_digest(self, "final_report_sha256")
        return self


class ProvisionalEvaluationInput(StrictContract):
    schema_version: Literal["itda.phase4-provisional-evaluation-input.v1"]
    authority: BenchmarkAuthorityBinding
    experiment: BenchmarkExperiment
    cases: Annotated[tuple[BenchmarkCase, ...], Field(min_length=1)]
    review_inventory: tuple[HumanReviewInventoryItem, ...]
    sensitivity: tuple[SensitivityEvidence, ...]
    generated_at: datetime
    input_sha256: Sha256

    @field_validator("generated_at")
    @classmethod
    def validate_generated_at(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="generated_at")

    @model_validator(mode="after")
    def validate_authority(self) -> Self:
        if (
            self.experiment.authority_binding_sha256 != self.authority.authority_binding_sha256
            or self.experiment.dev_authority_sha256 != self.authority.dev_authority_sha256
            or self.experiment.selection_manifest_sha256 != self.authority.selection_manifest_sha256
            or self.experiment.prediction_batch_sha256 != self.authority.prediction_batch_sha256
            or self.experiment.dev_case_inventory_sha256 != self.authority.dev_case_inventory_sha256
            or self.experiment.label_case_inventory_sha256
            != self.authority.label_case_inventory_sha256
            or self.experiment.prediction_case_records_sha256
            != self.authority.prediction_case_records_sha256
            or self.experiment.label_case_records_sha256
            != self.authority.label_case_records_sha256
            or self.experiment.review_inventory_sha256
            != self.authority.review_inventory_sha256
        ):
            raise ValueError("benchmark experiment does not match evaluator authority")
        _require_self_digest(self, "input_sha256")
        return self


class FinalizationInput(StrictContract):
    schema_version: Literal["itda.phase4-finalization-input.v1"]
    provisional: ProvisionalBenchmarkReport
    selected_config_sha256: Sha256
    human_review: HumanVisibleEvidenceReviewManifest | None = None
    zero_image_fallback: ZeroImageFallbackProof | None = None
    external_evidence_complete: StrictBool
    finalized_at: datetime
    input_sha256: Sha256

    @field_validator("finalized_at")
    @classmethod
    def validate_finalized_at(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="finalized_at")

    @model_validator(mode="after")
    def validate_input(self) -> Self:
        _require_self_digest(self, "input_sha256")
        return self


def _metric(values: list[float], *, reason: str) -> MetricValue:
    if not values:
        return MetricValue(value=None, numerator=0, denominator=0, undefined_reason=reason)
    value = sum(values) / len(values)
    return MetricValue(value=float(value), numerator=len(values), denominator=len(values))


def _ratio(numerator: int, denominator: int, *, reason: str) -> MetricValue:
    if denominator == 0:
        return MetricValue(value=None, numerator=0, denominator=0, undefined_reason=reason)
    return MetricValue(
        value=float(numerator / denominator), numerator=numerator, denominator=denominator
    )


def _median_scores(case: BenchmarkCase) -> dict[str, int | None]:
    repeat_maps = [repeat.scores.as_mapping() for repeat in case.candidate_repeats]
    result: dict[str, int | None] = {}
    for attribute_id in ATTRIBUTE_IDS:
        values = [mapping[attribute_id] for mapping in repeat_maps]
        observed = [value for value in values if value is not None]
        if not observed:
            result[attribute_id] = None
            continue
        ordered = sorted(observed)
        midpoint = len(ordered) // 2
        result[attribute_id] = (
            ordered[midpoint]
            if len(ordered) % 2 == 1
            else (ordered[midpoint - 1] + ordered[midpoint] + 1) // 2
        )
    return result


def _axis_score(scores: Mapping[str, int | None], axis_id: AxisId) -> int | None:
    values = [scores[attribute] for attribute in _AXIS_ATTRIBUTES[axis_id]]
    if any(value is None for value in values):
        return None
    return int((sum(value for value in values if value is not None) + 2) // 4)


def _derive_display_label(scores: Mapping[str, int | None]) -> str:
    axes = {axis_id: _axis_score(scores, axis_id) for axis_id in _AXIS_ATTRIBUTES}
    if any(value is None for value in axes.values()):
        raise ValueError("D-21 display label requires all three derived axes")
    tie_order = {axis_id: index for index, axis_id in enumerate(("H", "E", "R"))}
    ranked = sorted(
        ((axis_id, int(value)) for axis_id, value in axes.items() if value is not None),
        key=lambda row: (-row[1], tie_order[row[0]]),
    )
    top, second = ranked[:2]
    gap_milli = top[1] - second[1]
    label_ids = {
        "H": "history-tradition",
        "E": "emotion-image",
        "R": "rest-immersion",
    }
    policy = CANONICAL_FUSION_POLICY
    if (
        top[1] >= policy.label_single_min_percent * 40
        and gap_milli >= policy.label_single_gap_min_percent * 40
    ):
        return f"{label_ids[top[0]]}-type"
    if (
        second[1] >= policy.label_composite_min_percent * 40
        and gap_milli < policy.label_composite_gap_exclusive_percent * 40
    ):
        return f"{label_ids[top[0]]}+{label_ids[second[0]]}"
    return "mixed-experience"


def _average_ranks(values: list[float]) -> list[float]:
    ordered = sorted(enumerate(values), key=lambda row: row[1])
    ranks = [0.0] * len(values)
    index = 0
    while index < len(ordered):
        end = index + 1
        while end < len(ordered) and ordered[end][1] == ordered[index][1]:
            end += 1
        rank = (index + 1 + end) / 2.0
        for original_index, _ in ordered[index:end]:
            ranks[original_index] = rank
        index = end
    return ranks


def _spearman(predicted: list[float], expected: list[float]) -> float | None:
    if len(predicted) < 2 or len(set(predicted)) < 2 or len(set(expected)) < 2:
        return None
    left = _average_ranks(predicted)
    right = _average_ranks(expected)
    left_mean = sum(left) / len(left)
    right_mean = sum(right) / len(right)
    numerator = sum((a - left_mean) * (b - right_mean) for a, b in zip(left, right, strict=True))
    denominator = math.sqrt(
        sum((a - left_mean) ** 2 for a in left) * sum((b - right_mean) ** 2 for b in right)
    )
    return None if denominator == 0 else numerator / denominator


def _macro_f1(predicted: list[str], expected: list[str]) -> float | None:
    if not predicted:
        return None
    labels = sorted(set(predicted) | set(expected))
    scores: list[float] = []
    for label in labels:
        true_positive = sum(
            p == label and e == label for p, e in zip(predicted, expected, strict=True)
        )
        false_positive = sum(
            p == label and e != label for p, e in zip(predicted, expected, strict=True)
        )
        false_negative = sum(
            p != label and e == label for p, e in zip(predicted, expected, strict=True)
        )
        denominator = 2 * true_positive + false_positive + false_negative
        scores.append(0.0 if denominator == 0 else 2 * true_positive / denominator)
    return sum(scores) / len(scores)


def benchmark_evidence_roots(
    cases: tuple[BenchmarkCase, ...],
    review_inventory: tuple[HumanReviewInventoryItem, ...],
) -> tuple[str, str, str]:
    """Commit exact ordered prediction, label, and review records for evaluation."""

    prediction_records = [
        {
            "case_ref": case.case_ref,
            "image_medium_state": case.image_medium_state.value,
            "candidate_repeats": [
                repeat.model_dump(mode="json") for repeat in case.candidate_repeats
            ],
            "candidate_display_label": case.candidate_display_label,
            "visible_claim_count": case.visible_claim_count,
            "automatic_supported_claim_count": case.automatic_supported_claim_count,
            "named_failures": list(case.named_failures),
        }
        for case in cases
    ]
    label_records = [
        {
            "case_ref": case.case_ref,
            "baseline_scores": case.baseline_scores.model_dump(mode="json"),
            "dev_label_scores": case.dev_label_scores.model_dump(mode="json"),
            "baseline_display_label": case.baseline_display_label,
            "dev_display_label": case.dev_display_label,
            "confidence_percent": case.confidence_percent,
        }
        for case in cases
    ]
    review_records = [item.model_dump(mode="json") for item in review_inventory]
    return (
        canonical_sha256(prediction_records),
        canonical_sha256(label_records),
        canonical_sha256(review_records),
    )


def _optional_metric(value: float | None, count: int, reason: str) -> MetricValue:
    if value is None:
        return MetricValue(value=None, numerator=0, denominator=0, undefined_reason=reason)
    return MetricValue(value=float(value), numerator=count, denominator=count)


def _paired_bootstrap_interval(
    *,
    per_case_improvements: tuple[tuple[str, float], ...],
    seed: int,
) -> BootstrapInterval:
    inventory_sha256 = canonical_sha256(
        [{"case_ref": case_ref, "improvement": value} for case_ref, value in per_case_improvements]
    )
    if not per_case_improvements:
        return BootstrapInterval(
            confidence_bp=9500,
            seed=seed,
            resample_count=2000,
            eligible_inventory_sha256=inventory_sha256,
            eligible_count=0,
            estimate=None,
            lower=None,
            upper=None,
            undefined_reason="no paired candidate-defined case cohort",
        )
    values = tuple(value for _, value in per_case_improvements)
    sample_size = len(values)
    estimates: list[float] = []
    for resample_index in range(2000):
        sample = tuple(
            values[
                int.from_bytes(
                    hashlib.sha256(
                        f"{seed}:{resample_index}:{draw_index}".encode()
                    ).digest()[:8],
                    "big",
                )
                % sample_size
            ]
            for draw_index in range(sample_size)
        )
        estimates.append(statistics.fmean(sample))
    estimates.sort()
    return BootstrapInterval(
        confidence_bp=9500,
        seed=seed,
        resample_count=2000,
        eligible_inventory_sha256=inventory_sha256,
        eligible_count=sample_size,
        estimate=statistics.fmean(values),
        lower=estimates[49],
        upper=estimates[1949],
        undefined_reason=None,
    )


def build_provisional_report(
    *,
    experiment: BenchmarkExperiment,
    cases: tuple[BenchmarkCase, ...],
    review_inventory: tuple[HumanReviewInventoryItem, ...],
    sensitivity: tuple[SensitivityEvidence, ...],
    generated_at: datetime,
) -> ProvisionalBenchmarkReport:
    if not cases:
        raise ValueError("benchmark requires at least one explicit terminal case")
    if len({case.case_ref for case in cases}) != len(cases):
        raise ValueError("benchmark case references must be unique")
    if experiment.evaluation_scope == "DEV_24_PROTECTED" and len(cases) != 24:
        raise ValueError("protected DEV benchmark requires the exact 24-case authority cohort")
    if experiment.evaluation_scope == "DEV_24_PROTECTED":
        ordered_case_refs = tuple(case.case_ref for case in cases)
        inventory_sha256 = canonical_sha256(list(ordered_case_refs))
        prediction_root, label_root, review_root = benchmark_evidence_roots(
            cases,
            review_inventory,
        )
        if ordered_case_refs != tuple(sorted(ordered_case_refs)):
            raise ValueError("protected DEV benchmark cases require canonical authority order")
        if (
            experiment.dev_case_inventory_sha256 != inventory_sha256
            or experiment.label_case_inventory_sha256 != inventory_sha256
            or experiment.prediction_case_records_sha256 != prediction_root
            or experiment.label_case_records_sha256 != label_root
            or experiment.review_inventory_sha256 != review_root
        ):
            raise ValueError(
                "protected DEV benchmark evidence does not match authority roots"
            )
    if any(
        repeat.prediction_batch_sha256 != experiment.prediction_batch_sha256
        for case in cases
        for repeat in case.candidate_repeats
    ):
        raise ValueError("benchmark repeat does not bind the frozen prediction batch")
    all_repeats = tuple(repeat for case in cases for repeat in case.candidate_repeats)
    execution_receipts = tuple(repeat.execution_receipt_sha256 for repeat in all_repeats)
    request_identities = tuple(repeat.request_identity_sha256 for repeat in all_repeats)
    raw_prediction_refs = tuple(
        repeat.raw_prediction_ref
        for repeat in all_repeats
        if repeat.raw_prediction_ref is not None
    )
    if experiment.evaluation_scope == "DEV_24_PROTECTED" and (
        len(set(execution_receipts)) != len(execution_receipts)
        or len(set(request_identities)) != len(request_identities)
        or len(set(raw_prediction_refs)) != len(raw_prediction_refs)
    ):
        raise ValueError("scheduled benchmark execution evidence must be globally single-use")
    candidate_maps = {case.case_ref: _median_scores(case) for case in cases}
    for case in cases:
        claimed_labels = {
            "baseline": case.baseline_display_label,
            "dev": case.dev_display_label,
        }
        derived_labels = {
            "baseline": _derive_display_label(case.baseline_scores.as_mapping()),
            "dev": _derive_display_label(case.dev_label_scores.as_mapping()),
        }
        candidate = candidate_maps[case.case_ref]
        if any(value is not None for value in candidate.values()):
            claimed_labels["candidate"] = case.candidate_display_label
            derived_labels["candidate"] = _derive_display_label(candidate)
        drifted = tuple(
            lane for lane, derived in derived_labels.items() if claimed_labels[lane] != derived
        )
        if drifted:
            raise ValueError(
                f"D-21 display label claim drifted for {case.case_ref}: {','.join(drifted)}"
            )
    usable_cases = [
        case
        for case in cases
        if case.image_medium_state is ImageMediumState.QUALIFIED
        and any(value is not None for value in candidate_maps[case.case_ref].values())
    ]

    schema_numerator = sum(
        repeat.schema_compliant for case in cases for repeat in case.candidate_repeats
    )
    schema_denominator = len(cases) * 3
    stable_units = 0
    raw_differences: list[float] = []
    for case in usable_cases:
        terminal_same = len({repeat.terminal_status for repeat in case.candidate_repeats}) == 1
        masks = [
            tuple(value is not None for value in repeat.scores.as_mapping().values())
            for repeat in case.candidate_repeats
        ]
        stable_units += int(terminal_same and masks[0] == masks[1] == masks[2])
        for attribute_id in ATTRIBUTE_IDS:
            values = [repeat.scores.as_mapping()[attribute_id] for repeat in case.candidate_repeats]
            if all(value is not None for value in values):
                numeric = [int(value) for value in values if value is not None]
                raw_differences.extend(
                    abs(numeric[left] - numeric[right]) / 1_000
                    for left, right in ((0, 1), (0, 2), (1, 2))
                )

    baseline_errors: list[float] = []
    candidate_errors: list[float] = []
    baseline_candidate_agreement: list[float] = []
    candidate_label_agreement: list[float] = []
    baseline_errors_by_attribute: dict[str, list[float]] = {
        attribute_id: [] for attribute_id in ATTRIBUTE_IDS
    }
    candidate_errors_by_attribute: dict[str, list[float]] = {
        attribute_id: [] for attribute_id in ATTRIBUTE_IDS
    }
    missing_attribute_count = 0
    rank_scores: list[tuple[str, int]] = []
    axis_metrics: list[AxisMetric] = []
    baseline_axis_by_case: dict[str, dict[str, int | None]] = {}
    candidate_axis_by_case: dict[str, dict[str, int | None]] = {}
    label_axis_by_case: dict[str, dict[str, int | None]] = {}
    for case in cases:
        baseline = case.baseline_scores.as_mapping()
        candidate = candidate_maps[case.case_ref]
        labels = case.dev_label_scores.as_mapping()
        missing_attribute_count += sum(value is None for value in candidate.values())
        baseline_axis_by_case[case.case_ref] = {
            axis: _axis_score(baseline, axis) for axis in _AXIS_ATTRIBUTES
        }
        candidate_axis_by_case[case.case_ref] = {
            axis: _axis_score(candidate, axis) for axis in _AXIS_ATTRIBUTES
        }
        label_axis_by_case[case.case_ref] = {
            axis: _axis_score(labels, axis) for axis in _AXIS_ATTRIBUTES
        }
        defined_rank_axes = [
            value for value in candidate_axis_by_case[case.case_ref].values() if value is not None
        ]
        if defined_rank_axes:
            rank_scores.append((case.case_ref, sum(defined_rank_axes) // len(defined_rank_axes)))
    for case in usable_cases:
        baseline = case.baseline_scores.as_mapping()
        candidate = candidate_maps[case.case_ref]
        labels = case.dev_label_scores.as_mapping()
        for attribute_id in ATTRIBUTE_IDS:
            candidate_value = candidate[attribute_id]
            if candidate_value is None:
                continue
            baseline_value = baseline[attribute_id]
            label_value = labels[attribute_id]
            if baseline_value is None or label_value is None:
                continue
            baseline_errors.append(abs(baseline_value - label_value) / 1_000)
            candidate_errors.append(abs(candidate_value - label_value) / 1_000)
            baseline_errors_by_attribute[attribute_id].append(
                abs(baseline_value - label_value) / 1_000
            )
            candidate_errors_by_attribute[attribute_id].append(
                abs(candidate_value - label_value) / 1_000
            )
            baseline_candidate_agreement.append(1.0 - abs(baseline_value - candidate_value) / 4_000)
            candidate_label_agreement.append(1.0 - abs(candidate_value - label_value) / 4_000)

    for axis_id in _AXIS_ATTRIBUTES:
        baseline_axis_errors: list[float] = []
        candidate_axis_errors: list[float] = []
        for case in usable_cases:
            baseline_axis = baseline_axis_by_case[case.case_ref][axis_id]
            candidate_axis = candidate_axis_by_case[case.case_ref][axis_id]
            label_axis = label_axis_by_case[case.case_ref][axis_id]
            if baseline_axis is None or candidate_axis is None or label_axis is None:
                continue
            baseline_axis_errors.append(abs(baseline_axis - label_axis) / 40)
            candidate_axis_errors.append(abs(candidate_axis - label_axis) / 40)
        baseline_metric = _metric(
            baseline_axis_errors, reason="axis has no defined baseline cohort"
        )
        candidate_metric = _metric(
            candidate_axis_errors, reason="axis has no defined candidate cohort"
        )
        degradation = (
            None
            if baseline_metric.value is None or candidate_metric.value is None
            else candidate_metric.value - baseline_metric.value
        )
        axis_metrics.append(
            AxisMetric(
                axis_id=axis_id,
                baseline_mae=baseline_metric,
                candidate_mae=candidate_metric,
                candidate_degradation_points=degradation,
            )
        )

    baseline_spearman_values: list[float] = []
    candidate_spearman_values: list[float] = []
    for axis_id in _AXIS_ATTRIBUTES:
        rows = [
            (
                baseline_axis_by_case[case.case_ref][axis_id],
                candidate_axis_by_case[case.case_ref][axis_id],
                label_axis_by_case[case.case_ref][axis_id],
            )
            for case in usable_cases
        ]
        defined = [row for row in rows if all(value is not None for value in row)]
        if defined:
            baseline_spearman_value = _spearman(
                [float(row[0]) for row in defined if row[0] is not None],
                [float(row[2]) for row in defined if row[2] is not None],
            )
            candidate_spearman_value = _spearman(
                [float(row[1]) for row in defined if row[1] is not None],
                [float(row[2]) for row in defined if row[2] is not None],
            )
            if baseline_spearman_value is not None:
                baseline_spearman_values.append(baseline_spearman_value)
            if candidate_spearman_value is not None:
                candidate_spearman_values.append(candidate_spearman_value)

    baseline_f1 = _macro_f1(
        [case.baseline_display_label for case in usable_cases],
        [case.dev_display_label for case in usable_cases],
    )
    candidate_f1 = _macro_f1(
        [case.candidate_display_label for case in usable_cases],
        [case.dev_display_label for case in usable_cases],
    )
    baseline_mae = _metric(baseline_errors, reason="no candidate-defined label cohort")
    candidate_mae = _metric(candidate_errors, reason="no candidate-defined label cohort")
    attribute_metrics: list[AttributeMetric] = []
    for attribute_id in ATTRIBUTE_IDS:
        baseline_attribute_metric = _metric(
            baseline_errors_by_attribute[attribute_id],
            reason="attribute has no candidate-defined label cohort",
        )
        candidate_attribute_metric = _metric(
            candidate_errors_by_attribute[attribute_id],
            reason="attribute has no candidate-defined label cohort",
        )
        attribute_improvement = (
            None
            if baseline_attribute_metric.value is None or candidate_attribute_metric.value is None
            else baseline_attribute_metric.value - candidate_attribute_metric.value
        )
        attribute_metrics.append(
            AttributeMetric(
                attribute_id=attribute_id,
                baseline_mae=baseline_attribute_metric,
                candidate_mae=candidate_attribute_metric,
                improvement=_optional_metric(
                    attribute_improvement,
                    candidate_attribute_metric.denominator,
                    "attribute has no candidate-defined label cohort",
                ),
            )
        )
    improvement = (
        None
        if baseline_mae.value is None or candidate_mae.value is None
        else baseline_mae.value - candidate_mae.value
    )
    improvement_metric = _optional_metric(
        improvement, candidate_mae.denominator, "no candidate-defined label cohort"
    )
    per_case_improvements: list[tuple[str, float]] = []
    for case in usable_cases:
        baseline = case.baseline_scores.as_mapping()
        candidate = candidate_maps[case.case_ref]
        labels = case.dev_label_scores.as_mapping()
        paired: list[tuple[float, float]] = []
        for attribute_id in ATTRIBUTE_IDS:
            baseline_value = baseline[attribute_id]
            candidate_value = candidate[attribute_id]
            label_value = labels[attribute_id]
            if baseline_value is None or candidate_value is None or label_value is None:
                continue
            paired.append(
                (
                    abs(baseline_value - label_value) / 1_000,
                    abs(candidate_value - label_value) / 1_000,
                )
            )
        if paired:
            per_case_improvements.append(
                (
                    case.case_ref,
                    statistics.fmean(row[0] - row[1] for row in paired),
                )
            )
    improvement_interval = _paired_bootstrap_interval(
        per_case_improvements=tuple(per_case_improvements),
        seed=experiment.seed,
    )
    terminal_metric = _ratio(
        stable_units,
        len(usable_cases),
        reason="no eligible scheduled provider executions",
    )
    raw_metric = (
        MetricValue(
            value=float(statistics.median(raw_differences)),
            numerator=len(raw_differences),
            denominator=len(raw_differences),
        )
        if raw_differences
        else MetricValue(
            value=None,
            numerator=0,
            denominator=0,
            undefined_reason="no repeated observed scores",
        )
    )
    coverage = BenchmarkCoverage(
        total_count=len(cases),
        usable_count=len(usable_cases),
        by_state=tuple(
            CoverageByState(
                image_medium_state=state,
                total_count=sum(case.image_medium_state is state for case in cases),
                usable_count=sum(case.image_medium_state is state for case in usable_cases),
            )
            for state in ImageMediumState
        ),
    )
    max_axis_degradation = max(
        (
            row.candidate_degradation_points
            for row in axis_metrics
            if row.candidate_degradation_points is not None
        ),
        default=math.inf,
    )
    baseline_spearman = _metric(
        baseline_spearman_values, reason="Spearman requires at least two nonconstant cases"
    )
    candidate_spearman = _metric(
        candidate_spearman_values, reason="Spearman requires at least two nonconstant cases"
    )
    baseline_f1_metric = _optional_metric(
        baseline_f1, len(usable_cases), "Macro-F1 requires a defined label cohort"
    )
    candidate_f1_metric = _optional_metric(
        candidate_f1, len(usable_cases), "Macro-F1 requires a defined label cohort"
    )
    correlation_ok = (
        baseline_spearman.value is not None
        and candidate_spearman.value is not None
        and baseline_spearman.value - candidate_spearman.value <= 0.05
    )
    f1_ok = (
        baseline_f1_metric.value is not None
        and candidate_f1_metric.value is not None
        and baseline_f1_metric.value - candidate_f1_metric.value <= 0.05
    )
    noninferiority_ok = max_axis_degradation <= 6.25 and correlation_ok and f1_ok
    axis_metrics_tuple = (axis_metrics[0], axis_metrics[1], axis_metrics[2])
    metrics = BenchmarkMetrics(
        repeat_count=3,
        schema_compliance=_ratio(
            schema_numerator, schema_denominator, reason="no scheduled provider repeats"
        ),
        terminal_observability_agreement=terminal_metric,
        median_raw_score_difference=raw_metric,
        coverage=coverage,
        baseline_candidate_attribute_agreement=_metric(
            baseline_candidate_agreement, reason="no comparable baseline/candidate attributes"
        ),
        candidate_dev_label_agreement=_metric(
            candidate_label_agreement, reason="no comparable candidate/label attributes"
        ),
        automatic_visible_support_precision=_ratio(
            sum(case.automatic_supported_claim_count for case in cases),
            sum(case.visible_claim_count for case in cases),
            reason="no image-bearing visible claims",
        ),
        baseline_attribute_mae=baseline_mae,
        candidate_attribute_mae=candidate_mae,
        macro_attribute_mae_improvement=improvement_metric,
        macro_attribute_mae_improvement_ci95=improvement_interval,
        attribute_metrics=tuple(attribute_metrics),
        axis_metrics=axis_metrics_tuple,
        baseline_spearman=baseline_spearman,
        candidate_spearman=candidate_spearman,
        baseline_macro_f1=baseline_f1_metric,
        candidate_macro_f1=candidate_f1_metric,
        missing_attribute_count=missing_attribute_count,
        named_failures=tuple(
            sorted({failure for case in cases for failure in case.named_failures})
        ),
        candidate_rank_scores=tuple(sorted(rank_scores)),
        confidence_is_ranking_input=False,
        stability_gates_pass=(
            terminal_metric.value is not None
            and terminal_metric.value >= 0.95
            and raw_metric.value is not None
            and raw_metric.value <= 0.25
        ),
        noninferiority_gates_pass=noninferiority_ok,
        global_value_gates_pass=(
            improvement is not None
            and improvement >= 0.25
            and improvement_interval.lower is not None
            and improvement_interval.lower >= 0.0
            and noninferiority_ok
        ),
    )
    inventory = tuple(sorted(review_inventory, key=lambda item: item.inventory_item_sha256))
    fields: dict[str, object] = {
        "schema_version": "itda.phase4-provisional-benchmark.v1",
        "state": BenchmarkReportState.PROVISIONAL_PENDING_HUMAN_REVIEW,
        "experiment": experiment.model_dump(mode="json"),
        "cases": [case.model_dump(mode="json") for case in cases],
        "metrics": metrics.model_dump(mode="json"),
        "review_inventory": [item.model_dump(mode="json") for item in inventory],
        "sensitivity": [item.model_dump(mode="json") for item in sensitivity],
        "raw_prediction_refs": sorted(
            {
                repeat.raw_prediction_ref
                for case in cases
                for repeat in case.candidate_repeats
                if repeat.raw_prediction_ref is not None
            }
        ),
        "generated_at": _utc_text(generated_at),
    }
    return ProvisionalBenchmarkReport.model_validate(
        {**fields, "provisional_report_sha256": canonical_sha256(fields)}
    )


def _decision_report(**fields: object) -> BenchmarkDecisionReport:
    payload = {
        "schema_version": "itda.phase4-benchmark-decision.v1",
        **fields,
    }
    finalized_at = payload.get("finalized_at")
    if isinstance(finalized_at, datetime):
        payload["finalized_at"] = _utc_text(finalized_at)
    return BenchmarkDecisionReport.model_validate(
        {**payload, "final_report_sha256": canonical_sha256(payload)}
    )


def finalize_benchmark(
    *,
    provisional: ProvisionalBenchmarkReport,
    selected_config_sha256: str,
    finalized_at: datetime,
    human_review: HumanVisibleEvidenceReviewManifest | None = None,
    zero_image_fallback: ZeroImageFallbackProof | None = None,
    external_evidence_complete: bool = True,
) -> BenchmarkDecisionReport:
    independently_derived = build_provisional_report(
        experiment=provisional.experiment,
        cases=provisional.cases,
        review_inventory=provisional.review_inventory,
        sensitivity=provisional.sensitivity,
        generated_at=provisional.generated_at,
    )
    if independently_derived != provisional:
        raise ValueError("provisional benchmark does not equal its authoritative case derivation")
    sensitivity_digests = {item.config_sha256 for item in provisional.sensitivity}
    if selected_config_sha256 in sensitivity_digests:
        raise ValueError("SENSITIVITY_ONLY config cannot be selected for a terminal decision")
    if selected_config_sha256 != provisional.experiment.experiment_sha256:
        raise ValueError("selected config does not match the immutable benchmark experiment")
    locked_policy_sha256 = CANONICAL_FUSION_POLICY.policy_sha256
    undefined_visible = MetricValue(
        value=None,
        numerator=0,
        denominator=0,
        undefined_reason="human visible-evidence review not complete",
    )
    base_fields: dict[str, object] = {
        "provisional_report_sha256": provisional.provisional_report_sha256,
        "evaluation_scope": provisional.experiment.evaluation_scope,
        "dev_authority_sha256": provisional.experiment.dev_authority_sha256,
        "selected_config_sha256": selected_config_sha256,
        "locked_fusion_policy_sha256": locked_policy_sha256,
        "raw_artifact_refs": provisional.raw_prediction_refs,
        "finalized_at": finalized_at,
    }

    if zero_image_fallback is not None:
        visible_support = provisional.metrics.automatic_visible_support_precision
        if (
            provisional.metrics.coverage.usable_count != 0
            or provisional.review_inventory
            or human_review is not None
            or provisional.raw_prediction_refs
            or visible_support.numerator != 0
            or visible_support.denominator != 0
        ):
            raise ValueError("zero-image fallback requires zero image contributions and claims")
        if (
            zero_image_fallback.provisional_report_sha256 != provisional.provisional_report_sha256
            or zero_image_fallback.baseline_sha256 != provisional.experiment.baseline_sha256
        ):
            raise ValueError("zero-image fallback does not bind the exact provisional baseline")
        source_count = next(
            row.total_count
            for row in provisional.metrics.coverage.by_state
            if row.image_medium_state is zero_image_fallback.source_media_state
        )
        if source_count == 0:
            raise ValueError("zero-image fallback lineage is absent from the benchmark cohort")
        return _decision_report(
            **base_fields,
            state=zero_image_fallback.outcome,
            human_review_manifest_sha256=None,
            zero_image_fallback_sha256=zero_image_fallback.proof_sha256,
            visible_support_precision=undefined_visible.model_dump(mode="json"),
            adopted_attributes=(),
            inherited_baseline_attributes=ATTRIBUTE_IDS,
            failures=provisional.metrics.named_failures,
            reason="explicit zero-image fallback preserves the text and Odii baseline",
            image_contribution_count=0,
        )

    if not external_evidence_complete:
        return _decision_report(
            **base_fields,
            state=BenchmarkReportState.PENDING_EXTERNAL_EVIDENCE,
            human_review_manifest_sha256=None,
            zero_image_fallback_sha256=None,
            visible_support_precision=undefined_visible.model_dump(mode="json"),
            adopted_attributes=(),
            inherited_baseline_attributes=ATTRIBUTE_IDS,
            failures=provisional.metrics.named_failures,
            reason="required external evidence remains pending",
            image_contribution_count=len(provisional.review_inventory),
        )

    if human_review is None:
        return _decision_report(
            **base_fields,
            state=BenchmarkReportState.PROVISIONAL_PENDING_HUMAN_REVIEW,
            human_review_manifest_sha256=None,
            zero_image_fallback_sha256=None,
            visible_support_precision=undefined_visible.model_dump(mode="json"),
            adopted_attributes=(),
            inherited_baseline_attributes=ATTRIBUTE_IDS,
            failures=provisional.metrics.named_failures,
            reason="image-bearing metrics require complete human visible-evidence review",
            image_contribution_count=len(provisional.review_inventory),
        )

    if (
        human_review.prediction_batch_sha256 != provisional.experiment.prediction_batch_sha256
        or human_review.provisional_report_sha256 != provisional.provisional_report_sha256
        or human_review.selection_manifest_sha256
        != provisional.experiment.selection_manifest_sha256
        or human_review.expected_inventory != provisional.review_inventory
    ):
        raise ValueError("human review does not resolve the exact provisional inventory")

    supported_count = sum(
        entry.verdict is ReviewVerdict.SUPPORTED for entry in human_review.entries
    )
    visible_precision = _ratio(
        supported_count,
        len(human_review.entries),
        reason="human review contains no visible-evidence entries",
    )
    entries_by_id = {entry.inventory_item_sha256: entry for entry in human_review.entries}
    critical_rejected = any(
        item.critical
        and entries_by_id[item.inventory_item_sha256].verdict is not ReviewVerdict.SUPPORTED
        for item in human_review.expected_inventory
    )
    critical_failure_names = {
        "RIGHTS_CRITICAL_FAILURE",
        "SPLIT_CRITICAL_FAILURE",
        "SCHEMA_CRITICAL_FAILURE",
        "LINEAGE_CRITICAL_FAILURE",
        "PROVIDER_AUTHORITY_CRITICAL_FAILURE",
    }
    failures = set(provisional.metrics.named_failures)
    if critical_rejected:
        failures.add("CRITICAL_VISIBLE_EVIDENCE_REJECTED")
    critical_automatic_failure = bool(failures & critical_failure_names)
    automatic_safety_pass = (
        provisional.metrics.schema_compliance.value == 1.0
        and provisional.metrics.stability_gates_pass
        and visible_precision.value is not None
        and visible_precision.value >= 0.95
        and not critical_rejected
        and not critical_automatic_failure
    )
    improvements = {
        row.attribute_id: row.improvement.value for row in provisional.metrics.attribute_metrics
    }
    conditional_attributes: tuple[AttributeId, ...] = tuple(
        attribute_id
        for attribute_id in provisional.experiment.predeclared_conditional_attributes
        if (value := improvements[attribute_id]) is not None and value >= 0.25
    )
    adopted_attributes: tuple[AttributeId, ...]
    inherited_attributes: tuple[AttributeId, ...]
    if automatic_safety_pass and provisional.metrics.global_value_gates_pass:
        if provisional.experiment.evaluation_scope == "SYNTHETIC_PROVIDER_FREE":
            state = BenchmarkReportState.SYNTHETIC_EVALUATION_ONLY
            adopted_attributes = ()
            inherited_attributes = ATTRIBUTE_IDS
            reason = (
                "synthetic provider-free evidence is evaluation-only and cannot authorize release"
            )
        else:
            state = BenchmarkReportState.ADOPT
            adopted_attributes = ATTRIBUTE_IDS
            inherited_attributes = ()
            reason = "all critical, stability, visible-support, and global value gates passed"
    elif (
        automatic_safety_pass
        and provisional.metrics.noninferiority_gates_pass
        and conditional_attributes
    ):
        if provisional.experiment.evaluation_scope == "SYNTHETIC_PROVIDER_FREE":
            state = BenchmarkReportState.SYNTHETIC_EVALUATION_ONLY
            adopted_attributes = ()
            inherited_attributes = ATTRIBUTE_IDS
            reason = (
                "synthetic provider-free evidence is evaluation-only and cannot authorize release"
            )
        else:
            state = BenchmarkReportState.CONDITIONAL_ADOPT
            adopted_attributes = conditional_attributes
            inherited_attributes = tuple(
                attribute_id
                for attribute_id in ATTRIBUTE_IDS
                if attribute_id not in adopted_attributes
            )
            reason = "only predeclared passing attributes adopt; all others inherit baseline"
    else:
        state = BenchmarkReportState.REJECT
        adopted_attributes = ()
        inherited_attributes = ATTRIBUTE_IDS
        reason = "one or more critical, review, stability, or value gates failed"
    return _decision_report(
        **base_fields,
        state=state,
        human_review_manifest_sha256=human_review.review_manifest_sha256,
        zero_image_fallback_sha256=None,
        visible_support_precision=visible_precision.model_dump(mode="json"),
        adopted_attributes=adopted_attributes,
        inherited_baseline_attributes=inherited_attributes,
        failures=tuple(sorted(failures)),
        reason=reason,
        image_contribution_count=len(provisional.review_inventory),
    )


__all__ = [
    "ATTRIBUTE_IDS",
    "BenchmarkCase",
    "BootstrapInterval",
    "BenchmarkExperiment",
    "BenchmarkMetrics",
    "BenchmarkDecisionReport",
    "BenchmarkRepeat",
    "BenchmarkReportState",
    "BenchmarkScoreVector",
    "BenchmarkAuthorityBinding",
    "FinalizationInput",
    "HumanReviewInventoryItem",
    "HumanVisibleEvidenceReviewEntry",
    "HumanVisibleEvidenceReviewManifest",
    "ReviewVerdict",
    "ProvisionalEvaluationInput",
    "SensitivityEvidence",
    "ZeroImageFallbackProof",
    "benchmark_evidence_roots",
    "build_provisional_report",
    "bind_evaluator_authority",
    "finalize_benchmark",
]
