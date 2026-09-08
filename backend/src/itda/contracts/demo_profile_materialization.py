"""Strict contracts for the isolated Phase 5 DEV profile materializer.

The models in this module deliberately do not reuse ``ImageObservationV2``.
Provider output becomes useful only after it validates as a complete,
evidence-bound ``DEMO_MODEL_DERIVED`` profile.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import datetime
from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, ValidationInfo, field_validator, model_validator

from itda.contracts.base import Sha256, StrictContract, require_utc
from itda.contracts.hard_duplicate_adjudication import (
    HARD_DUPLICATE_ADJUDICATION_SHA256,
    HardDuplicateAdjudication,
    load_hard_duplicate_adjudication,
)
from itda.contracts.phase5_recovery_policy import (
    ACTIVATION_SUITE_SHA256,
    CANNOT_COAPPEAR_AUTHORITY_SHA256,
    CANONICAL_CONTRAST_PAIRS,
    CANONICAL_PHASE5_RECOVERY_POLICY,
    CANONICAL_SCENARIO_IDS,
    CONTRAST_SUITE_SHA256,
    ActivationScenarioResult,
    ContrastResult,
    validate_activation_scenario_results,
    validate_contrast_results,
)
from itda.domain.canonical import canonical_sha256

# The source/dataset identities are deliberately imported from the policy module
# through the policy instance below.  Keeping the contract fields explicit makes
# omission and map reduction impossible at the lifecycle boundary.
PHASE5_RECOVERY_CANDIDATE_SCHEMA = "itda.phase5-recovery-release-candidate.v1"
PHASE5_RELEASE_LIFECYCLE_SCHEMA = "itda.phase5-release-lifecycle.v1"
PHASE5_CANDIDATE_SMOKE_SCHEMA = "itda.phase5-candidate-smoke-attestation.v1"
PHASE5_ACTIVATION_INTENT_SCHEMA = "itda.phase5-activation-intent.v1"
PHASE5_PROMOTION_SCHEMA = "itda.phase5-promotion-receipt.v1"
PHASE5_INVALIDATION_SCHEMA = "itda.phase5-invalidation-receipt.v1"
PHASE5_ROLLBACK_SCHEMA = "itda.phase5-rollback-receipt.v1"
PHASE5_ACTIVATION_ATTESTATION_SCHEMA = "itda.phase5-activation-attestation.v1"


def _require_digest(value: object, *, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field_name} must be a lower-case SHA-256 digest")
    return value


def _validate_contrast_map_values(
    value: object,
    *,
    scenarios: tuple[ActivationScenarioResult, ...],
) -> tuple[ContrastResult, ...]:
    if isinstance(value, Mapping):
        keyed: dict[tuple[str, str], object] = {}
        for key, item in value.items():
            if isinstance(key, tuple) and len(key) == 2:
                keyed[(str(key[0]), str(key[1]))] = item
            elif isinstance(item, Mapping):
                keyed[(str(item.get("left_scenario_id")), str(item.get("right_scenario_id")))] = (
                    item
                )
            else:
                raise ValueError("contrast result map keys are invalid")
        return validate_contrast_results(keyed, scenarios=scenarios)
    if isinstance(value, (list, tuple)):
        keyed: dict[tuple[str, str], object] = {}
        for item in value:
            if isinstance(item, ContrastResult):
                key = (item.left_scenario_id, item.right_scenario_id)
            elif isinstance(item, Mapping):
                key = (str(item.get("left_scenario_id")), str(item.get("right_scenario_id")))
            else:
                raise ValueError("contrast result map item is invalid")
            keyed[key] = item
        return validate_contrast_results(keyed, scenarios=scenarios)
    raise ValueError("contrast result map is required")


def _validate_recovery_maps(
    scenario_results: Mapping[str, ActivationScenarioResult | Mapping[str, object]],
    contrast_results: object,
) -> tuple[dict[str, ActivationScenarioResult], tuple[ContrastResult, ...]]:
    scenarios = validate_activation_scenario_results(scenario_results)
    scenario_map = {scenario.scenario_id: scenario for scenario in scenarios}
    contrasts = _validate_contrast_map_values(contrast_results, scenarios=scenarios)
    return scenario_map, contrasts


def _recovery_child_digest(value: object, *, label: str) -> str:
    """Accept only a non-empty digest for a completed child proof."""

    return _require_digest(value, field_name=label)


def _validate_child_digests(values: Mapping[str, object], *, required: tuple[str, ...]) -> None:
    for field_name in required:
        _recovery_child_digest(values.get(field_name), label=field_name)


class Phase5ReleaseLifecycle(StrictContract):
    """Lifecycle head checked before any candidate or profile dereference."""

    schema_version: Literal["itda.phase5-release-lifecycle.v1"] = PHASE5_RELEASE_LIFECYCLE_SCHEMA
    candidate_sha256: Sha256
    state: Literal[
        "DRAFT_QUARANTINED",
        "SMOKE_COMPLETE",
        "PREPARED",
        "PROMOTED",
        "ACTIVE",
        "INVALIDATED",
        "QUARANTINED",
    ]
    generation_sha256: Sha256
    smoke_attestation_sha256: Sha256 | None = None
    activation_intent_sha256: Sha256 | None = None
    promotion_sha256: Sha256 | None = None
    activation_attestation_sha256: Sha256 | None = None
    invalidation_sha256: Sha256 | None = None
    rollback_sha256: Sha256 | None = None
    previous_release_sha256: Sha256 | None = None
    expected_current_sha256: Sha256 | None = None
    lifecycle_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_lifecycle(self) -> Self:
        if self.state == "DRAFT_QUARANTINED" and any(
            value is not None
            for value in (
                self.smoke_attestation_sha256,
                self.activation_intent_sha256,
                self.promotion_sha256,
                self.activation_attestation_sha256,
            )
        ):
            raise ValueError("draft lifecycle cannot claim downstream evidence")
        if self.state == "SMOKE_COMPLETE" and self.smoke_attestation_sha256 is None:
            raise ValueError("smoke-complete lifecycle requires smoke attestation")
        if self.state == "PREPARED" and (
            self.smoke_attestation_sha256 is None or self.activation_intent_sha256 is None
        ):
            raise ValueError("prepared lifecycle requires smoke and activation intent")
        if self.state == "PROMOTED" and (
            self.activation_intent_sha256 is None or self.promotion_sha256 is None
        ):
            raise ValueError("promoted lifecycle requires activation intent and promotion")
        if self.state == "ACTIVE" and (
            self.smoke_attestation_sha256 is None
            or self.activation_intent_sha256 is None
            or self.promotion_sha256 is None
            or self.activation_attestation_sha256 is None
        ):
            raise ValueError("active lifecycle requires complete positive attestation")
        if self.state in {"INVALIDATED", "QUARANTINED"} and self.invalidation_sha256 is None:
            raise ValueError("denial lifecycle requires invalidation evidence")
        _require_self_digest(self, digest_field="lifecycle_sha256")
        return self


class Phase5RecoveryActivePointer(StrictContract):
    """Recovery pointer bound to lifecycle, promotion, and positive attestation."""

    schema_version: Literal["itda.phase5-recovery-active-pointer.v1"] = (
        "itda.phase5-recovery-active-pointer.v1"
    )
    state: Literal["PROMOTED", "ACTIVE"]
    active_release_sha256: Sha256
    previous_release_sha256: Sha256 | None
    expected_current_sha256: Sha256 | None
    promotion_sha256: Sha256
    activation_attestation_sha256: Sha256 | None = None
    pointer_sha256: Sha256

    @model_validator(mode="after")
    def validate_pointer(self) -> Self:
        if self.previous_release_sha256 != self.expected_current_sha256:
            raise ValueError("recovery pointer CAS predecessor drifted")
        if self.state == "ACTIVE" and self.activation_attestation_sha256 is None:
            raise ValueError("active recovery pointer requires positive attestation")
        if self.state == "PROMOTED" and self.activation_attestation_sha256 is not None:
            raise ValueError("promoted recovery pointer cannot claim positive attestation")
        _require_self_digest(self, digest_field="pointer_sha256")
        return self


class Phase5RecoveryReleaseCandidate(StrictContract):
    """Additive D-36 candidate; it is quarantined until a later promotion."""

    schema_version: Literal["itda.phase5-recovery-release-candidate.v1"] = (
        PHASE5_RECOVERY_CANDIDATE_SCHEMA
    )
    state: Literal["DRAFT_QUARANTINED"] = "DRAFT_QUARANTINED"
    analysis_origin: Literal["DEMO_MODEL_DERIVED"] = "DEMO_MODEL_DERIVED"
    model: Literal["glm-5v-turbo", "minimaxai/minimax-m3"]
    prompt_version: Literal[
        "phase5-demo-profile.v1",
        "phase5-demo-profile-json.v2",
        "phase5-demo-profile-sentinel-json.v4",
        "phase5-demo-profile-sentinel-json.v5",
    ]
    generation_sha256: Sha256
    generation_receipt_sha256: Sha256
    membership_sha256: Sha256
    hard_duplicate_adjudication_sha256: Sha256
    cannot_coappear_authority_sha256: Sha256
    policy_sha256: Sha256
    structural_profile_count: Literal[24] = 24
    candidate_profile_count: Annotated[int, Field(strict=True, ge=0, le=24)]
    post_hard_duplicate_count: Annotated[int, Field(strict=True, ge=0, le=24)]
    post_cannot_coappear_count: Annotated[int, Field(strict=True, ge=0, le=24)]
    effective_candidate_count: Annotated[int, Field(strict=True, ge=0, le=24)]
    confidence_is_ranking_input: Literal[False] = False
    source_inventory_sha256: Sha256
    config_sha256: Sha256
    checkout_sha256: Sha256
    kernel_sha256: Sha256
    activation_source_file_sha256: Sha256
    activation_dataset_sha256: Sha256
    activation_suite_sha256: Sha256
    scenario_results: dict[str, ActivationScenarioResult]
    contrast_suite_sha256: Sha256
    contrast_results: tuple[ContrastResult, ...]
    profiles: Annotated[
        tuple[DemoModelDerivedProfile | NvidiaMinimaxModelDerivedProfile, ...],
        Field(min_length=24, max_length=24),
    ]
    release_sha256: Sha256

    @model_validator(mode="before")
    @classmethod
    def normalize_map_inputs(cls, value: object) -> object:
        if not isinstance(value, Mapping):
            return value
        payload = dict(value)
        scenario_value = payload.get("scenario_results")
        contrast_value = payload.get("contrast_results")
        if isinstance(scenario_value, (list, tuple)):
            payload["scenario_results"] = {
                str(item.get("scenario_id")): item
                for item in scenario_value
                if isinstance(item, Mapping)
            }
        if isinstance(contrast_value, Mapping):
            payload["contrast_results"] = tuple(contrast_value.values())
        return payload

    @model_validator(mode="after")
    def validate_recovery_candidate(self) -> Self:
        policy = CANONICAL_PHASE5_RECOVERY_POLICY
        place_ids = tuple(profile.place_id for profile in self.profiles)
        if place_ids != tuple(sorted(place_ids)) or len(set(place_ids)) != 24:
            raise ValueError("recovery candidate requires exact canonical unique membership")
        if self.membership_sha256 != canonical_sha256(list(place_ids)):
            raise ValueError("recovery candidate membership digest drifted")
        if self.policy_sha256 != policy.policy_sha256:
            raise ValueError("recovery candidate policy identity drifted")
        if self.hard_duplicate_adjudication_sha256 != policy.hard_duplicate_adjudication_sha256:
            raise ValueError("recovery candidate hard-duplicate identity drifted")
        if (
            self.cannot_coappear_authority_sha256
            != policy.cannot_coappear_authority.authority_sha256
        ):
            raise ValueError("recovery candidate cannot-coappear identity drifted")
        if self.activation_source_file_sha256 != policy.activation_source_file_sha256:
            raise ValueError("recovery candidate scenario source identity drifted")
        if self.activation_dataset_sha256 != policy.activation_dataset_sha256:
            raise ValueError("recovery candidate scenario dataset identity drifted")
        if self.activation_suite_sha256 != policy.activation_suite_sha256:
            raise ValueError("recovery candidate activation suite identity drifted")
        scenarios, contrasts = _validate_recovery_maps(self.scenario_results, self.contrast_results)
        if tuple(scenarios) != CANONICAL_SCENARIO_IDS:
            raise ValueError("recovery candidate scenario map is incomplete")
        if tuple(row.pair for row in contrasts) != CANONICAL_CONTRAST_PAIRS:
            raise ValueError("recovery candidate contrast map is incomplete")
        if self.contrast_suite_sha256 != policy.contrast_suite_sha256:
            raise ValueError("recovery candidate contrast suite identity drifted")
        candidate_ids = tuple(
            profile.place_id
            for profile in self.profiles
            if profile.confidence >= policy.candidate_confidence_min
        )
        if self.candidate_profile_count != len(candidate_ids):
            raise ValueError("recovery candidate confidence count drifted")
        hard_duplicate = load_hard_duplicate_adjudication()
        group_ids = {hard_duplicate.group_id_by_place[place_id] for place_id in candidate_ids}
        if self.post_hard_duplicate_count != len(group_ids):
            raise ValueError("recovery candidate hard-duplicate count drifted")
        selected: list[str] = []
        for place_id in candidate_ids:
            group_id = hard_duplicate.group_id_by_place[place_id]
            if any(
                policy.cannot_coappear_authority.forbids(place_id, selected_place)
                for selected_place in selected
            ):
                continue
            if group_id not in {hard_duplicate.group_id_by_place[item] for item in selected}:
                selected.append(place_id)
        if self.post_cannot_coappear_count != len(selected):
            raise ValueError("recovery candidate cannot-coappear count drifted")
        if self.effective_candidate_count != len(selected):
            raise ValueError("recovery candidate effective count drifted")
        if self.effective_candidate_count < policy.minimum_effective_candidate_count:
            raise ValueError("recovery candidate has insufficient effective capacity")
        _require_self_digest(self, digest_field="release_sha256")
        return self


# Descriptive aliases keep downstream code from creating alternate contracts.
Phase5DemoRecoveryReleaseCandidate = Phase5RecoveryReleaseCandidate
Phase5QuarantinedReleaseCandidate = Phase5RecoveryReleaseCandidate


class Phase5CandidateSmokeAttestation(StrictContract):
    """Complete candidate-scoped smoke proof required before activation intent."""

    schema_version: Literal["itda.phase5-candidate-smoke-attestation.v1"] = (
        PHASE5_CANDIDATE_SMOKE_SCHEMA
    )
    state: Literal["COMPLETE"] = "COMPLETE"
    candidate_sha256: Sha256
    release_sha256: Sha256
    generation_sha256: Sha256
    generation_receipt_sha256: Sha256
    membership_sha256: Sha256
    source_inventory_sha256: Sha256
    checkout_sha256: Sha256
    config_sha256: Sha256
    kernel_sha256: Sha256
    policy_sha256: Sha256
    hard_duplicate_adjudication_sha256: Sha256
    cannot_coappear_authority_sha256: Sha256
    activation_source_file_sha256: Sha256
    activation_dataset_sha256: Sha256
    activation_suite_sha256: Sha256
    scenario_results: dict[str, ActivationScenarioResult]
    contrast_suite_sha256: Sha256
    contrast_results: tuple[ContrastResult, ...]
    backend_digest: Sha256
    storage_digest: Sha256
    evidence_digest: Sha256
    ordinary_unavailable_digest: Sha256
    browser_digest: Sha256
    smoke_attestation_sha256: Sha256

    @model_validator(mode="before")
    @classmethod
    def normalize_maps(cls, value: object) -> object:
        if not isinstance(value, Mapping):
            return value
        payload = dict(value)
        if isinstance(payload.get("scenario_results"), (list, tuple)):
            payload["scenario_results"] = {
                str(item.get("scenario_id")): item
                for item in payload["scenario_results"]
                if isinstance(item, Mapping)
            }
        if isinstance(payload.get("contrast_results"), Mapping):
            payload["contrast_results"] = tuple(payload["contrast_results"].values())
        return payload

    @model_validator(mode="after")
    def validate_smoke(self) -> Self:
        policy = CANONICAL_PHASE5_RECOVERY_POLICY
        scenarios, contrasts = _validate_recovery_maps(self.scenario_results, self.contrast_results)
        if self.policy_sha256 != policy.policy_sha256:
            raise ValueError("smoke policy identity drifted")
        if self.hard_duplicate_adjudication_sha256 != policy.hard_duplicate_adjudication_sha256:
            raise ValueError("smoke hard-duplicate identity drifted")
        if (
            self.cannot_coappear_authority_sha256
            != policy.cannot_coappear_authority.authority_sha256
        ):
            raise ValueError("smoke cannot-coappear identity drifted")
        if self.activation_source_file_sha256 != policy.activation_source_file_sha256:
            raise ValueError("smoke scenario source identity drifted")
        if self.activation_dataset_sha256 != policy.activation_dataset_sha256:
            raise ValueError("smoke scenario dataset identity drifted")
        if self.activation_suite_sha256 != policy.activation_suite_sha256:
            raise ValueError("smoke suite identity drifted")
        if self.contrast_suite_sha256 != policy.contrast_suite_sha256:
            raise ValueError("smoke contrast suite identity drifted")
        _validate_child_digests(
            self.model_dump(mode="json"),
            required=(
                "backend_digest",
                "storage_digest",
                "evidence_digest",
                "ordinary_unavailable_digest",
                "browser_digest",
            ),
        )
        if (
            tuple(scenarios) != CANONICAL_SCENARIO_IDS
            or tuple(row.pair for row in contrasts) != CANONICAL_CONTRAST_PAIRS
        ):
            raise ValueError("smoke maps are incomplete")
        _require_self_digest(self, digest_field="smoke_attestation_sha256")
        return self


class Phase5ActivationIntent(StrictContract):
    """Immutable PREPARED intent reopened before any promotion mutation."""

    schema_version: Literal["itda.phase5-activation-intent.v1"] = PHASE5_ACTIVATION_INTENT_SCHEMA
    state: Literal["PREPARED"] = "PREPARED"
    candidate_sha256: Sha256
    smoke_attestation_sha256: Sha256
    expected_current_sha256: Sha256 | None
    policy_sha256: Sha256
    hard_duplicate_adjudication_sha256: Sha256
    cannot_coappear_authority_sha256: Sha256
    activation_suite_sha256: Sha256
    contrast_suite_sha256: Sha256
    intent_sha256: Sha256

    @model_validator(mode="after")
    def validate_intent(self) -> Self:
        if self.policy_sha256 != CANONICAL_PHASE5_RECOVERY_POLICY.policy_sha256:
            raise ValueError("activation intent policy identity drifted")
        if (
            self.hard_duplicate_adjudication_sha256
            != CANONICAL_PHASE5_RECOVERY_POLICY.hard_duplicate_adjudication_sha256
        ):
            raise ValueError("activation intent hard-duplicate identity drifted")
        if (
            self.cannot_coappear_authority_sha256
            != CANONICAL_PHASE5_RECOVERY_POLICY.cannot_coappear_authority.authority_sha256
        ):
            raise ValueError("activation intent cannot-coappear identity drifted")
        _require_self_digest(self, digest_field="intent_sha256")
        return self


class Phase5PromotionReceipt(StrictContract):
    """CAS promotion record; PROMOTED is still denied until attestation."""

    schema_version: Literal["itda.phase5-promotion-receipt.v1"] = PHASE5_PROMOTION_SCHEMA
    state: Literal["PROMOTED"] = "PROMOTED"
    candidate_sha256: Sha256
    smoke_attestation_sha256: Sha256
    activation_intent_sha256: Sha256
    expected_current_sha256: Sha256 | None
    previous_release_sha256: Sha256 | None
    active_release_sha256: Sha256
    promotion_sha256: Sha256

    @model_validator(mode="after")
    def validate_promotion(self) -> Self:
        if self.active_release_sha256 != self.candidate_sha256:
            raise ValueError("promotion candidate differs from active release")
        if self.previous_release_sha256 != self.expected_current_sha256:
            raise ValueError("promotion CAS predecessor differs from expected current")
        _require_self_digest(self, digest_field="promotion_sha256")
        return self


class Phase5InvalidationReceipt(StrictContract):
    """Durable denial installed before any pointer rollback attempt."""

    schema_version: Literal["itda.phase5-invalidation-receipt.v1"] = PHASE5_INVALIDATION_SCHEMA
    state: Literal["INVALIDATED", "QUARANTINED"]
    candidate_sha256: Sha256
    promotion_sha256: Sha256 | None
    reason_code: Annotated[str, Field(strict=True, min_length=1, max_length=120)]
    invalidation_sha256: Sha256

    @model_validator(mode="after")
    def validate_invalidation(self) -> Self:
        _require_self_digest(self, digest_field="invalidation_sha256")
        return self


class Phase5RollbackReceipt(StrictContract):
    """Recorded rollback result; it cannot restore public authority by itself."""

    schema_version: Literal["itda.phase5-rollback-receipt.v1"] = PHASE5_ROLLBACK_SCHEMA
    state: Literal["ROLLBACK_SUCCEEDED", "ROLLBACK_FAILED"]
    candidate_sha256: Sha256
    previous_release_sha256: Sha256 | None
    active_release_sha256_before: Sha256
    error_code: Annotated[str, Field(strict=True, min_length=1, max_length=120)] | None = None
    rollback_sha256: Sha256

    @model_validator(mode="after")
    def validate_rollback(self) -> Self:
        if self.state == "ROLLBACK_FAILED" and self.error_code is None:
            raise ValueError("failed rollback requires safe error code")
        _require_self_digest(self, digest_field="rollback_sha256")
        return self


class Phase5ActivationAttestation(StrictContract):
    """Positive production proof; only this contract can leave lifecycle ACTIVE."""

    schema_version: Literal["itda.phase5-activation-attestation.v1"] = (
        PHASE5_ACTIVATION_ATTESTATION_SCHEMA
    )
    state: Literal["COMPLETE_POSITIVE"] = "COMPLETE_POSITIVE"
    candidate_sha256: Sha256
    smoke_attestation_sha256: Sha256
    activation_intent_sha256: Sha256
    promotion_sha256: Sha256
    policy_sha256: Sha256
    hard_duplicate_adjudication_sha256: Sha256
    cannot_coappear_authority_sha256: Sha256
    activation_suite_sha256: Sha256
    scenario_results: dict[str, ActivationScenarioResult]
    contrast_suite_sha256: Sha256
    contrast_results: tuple[ContrastResult, ...]
    ordinary_run_results: dict[str, Sha256]
    attestation_sha256: Sha256

    @model_validator(mode="before")
    @classmethod
    def normalize_maps(cls, value: object) -> object:
        if not isinstance(value, Mapping):
            return value
        payload = dict(value)
        if isinstance(payload.get("scenario_results"), (list, tuple)):
            payload["scenario_results"] = {
                str(item.get("scenario_id")): item
                for item in payload["scenario_results"]
                if isinstance(item, Mapping)
            }
        if isinstance(payload.get("contrast_results"), Mapping):
            payload["contrast_results"] = tuple(payload["contrast_results"].values())
        return payload

    @model_validator(mode="after")
    def validate_attestation(self) -> Self:
        policy = CANONICAL_PHASE5_RECOVERY_POLICY
        scenarios, contrasts = _validate_recovery_maps(self.scenario_results, self.contrast_results)
        if (
            self.policy_sha256 != policy.policy_sha256
            or self.hard_duplicate_adjudication_sha256 != policy.hard_duplicate_adjudication_sha256
            or self.cannot_coappear_authority_sha256
            != policy.cannot_coappear_authority.authority_sha256
        ):
            raise ValueError("activation attestation relation or policy identity drifted")
        if (
            self.activation_suite_sha256 != policy.activation_suite_sha256
            or self.contrast_suite_sha256 != policy.contrast_suite_sha256
        ):
            raise ValueError("activation attestation suite identity drifted")
        if (
            tuple(scenarios) != CANONICAL_SCENARIO_IDS
            or tuple(row.pair for row in contrasts) != CANONICAL_CONTRAST_PAIRS
        ):
            raise ValueError("activation attestation maps are incomplete")
        if tuple(self.ordinary_run_results) != CANONICAL_SCENARIO_IDS:
            raise ValueError("activation attestation ordinary map is incomplete")
        for digest in self.ordinary_run_results.values():
            _require_digest(digest, field_name="ordinary_run_result")
        _require_self_digest(self, digest_field="attestation_sha256")
        return self


# Compatibility aliases for callers that prefer the shorter receipt vocabulary.
CandidateSmokeAttestation = Phase5CandidateSmokeAttestation
ActivationIntent = Phase5ActivationIntent
PromotionReceipt = Phase5PromotionReceipt
InvalidationReceipt = Phase5InvalidationReceipt
RollbackReceipt = Phase5RollbackReceipt
ActivationAttestation = Phase5ActivationAttestation


GENERAL_PROFILE_BASE_URL = "https://api.z.ai/api/paas/v4"
PROFILE_ENDPOINT = f"{GENERAL_PROFILE_BASE_URL}/chat/completions"
CODING_PLAN_BASE_URL = "https://api.z.ai/api/coding/paas/v4"
CODING_PLAN_ENDPOINT = f"{CODING_PLAN_BASE_URL}/chat/completions"
PROFILE_MODEL = "glm-5v-turbo"
NVIDIA_PROFILE_ENDPOINT = "https://integrate.api.nvidia.com/v1/chat/completions"
NVIDIA_PROFILE_MODEL = "minimaxai/minimax-m3"
NVIDIA_PROVIDER_LANE = "NVIDIA_NIM_API"
_NVIDIA_V4_PROMPT_SHA256 = "762bc24e3a933796fedf9eb7cb620fb6f8f7efaa544d60e7bb6d6c4e4890e4b2"
_NVIDIA_V5_PROMPT_SHA256 = "aaa0328deaae58999b96eb9a43f176e589eb95319c3a80e9cd2978b23b925b3a"
_NVIDIA_V4_PROFILE_SCHEMA_SHA256 = (
    "c14c602586656420057e0e57c9693e3708ce69b285d74f4586e135c9cdbfb2c5"
)
_NVIDIA_V5_PROFILE_SCHEMA_SHA256 = (
    "85fec5e62a23e949c10e1ff6f9fceb8f27f1aaa8d766f3b86cc443f028844a3c"
)
_NVIDIA_CONFIG_SHA256 = "9c6061bac4c411f108f2328862a8439024928ba52ffdd64bf176a454cd78f90c"
NVIDIA_INITIAL_AUTHORITY_TEXT = (
    "approve-phase5-nvidia-nim:model=minimaxai/minimax-m3:"
    "endpoint=https://integrate.api.nvidia.com/v1/chat/completions:"
    "temperature=1:top-p=0.95:max-tokens=8192:new-http-attempts=30:"
    "probe-first=true"
)
NVIDIA_INITIAL_AUTHORITY_SHA256 = hashlib.sha256(
    NVIDIA_INITIAL_AUTHORITY_TEXT.encode("utf-8")
).hexdigest()
NVIDIA_TOOL_AUTHORITY_TEXT = (
    "approve-phase5-nvidia-minimax-json-v2:model=minimaxai/minimax-m3:"
    "endpoint=https://integrate.api.nvidia.com/v1/chat/completions:"
    "prompt-version=phase5-demo-profile-json.v2:temperature=0:top-p=0.95:"
    "max-tokens=8192:seed=0:thinking-mode=disabled:"
    "output-contract=required-named-tool-json-schema:"
    "response-format=omitted-undocumented-for-exact-model:"
    "new-http-attempts=30:probe-first=true"
)
NVIDIA_TOOL_AUTHORITY_SHA256 = hashlib.sha256(
    NVIDIA_TOOL_AUTHORITY_TEXT.encode("utf-8")
).hexdigest()
NVIDIA_JSON_START_SENTINEL = "<<<ITDA_PROFILE_JSON_V3_START_4F3A6C91>>>"
NVIDIA_JSON_END_SENTINEL = "<<<ITDA_PROFILE_JSON_V3_END_9B7D2E65>>>"
NVIDIA_MAX_BOUNDED_JSON_BYTES = 65_536
NVIDIA_AUTHORITY_TEXT = (
    "approve-phase5-nvidia-minimax-sentinel-json-v4:model=minimaxai/minimax-m3:"
    "endpoint=https://integrate.api.nvidia.com/v1/chat/completions:"
    "prompt-version=phase5-demo-profile-sentinel-json.v4:temperature=0:"
    "top-p=omitted-provider-default-0.95:max-tokens=8192:seed=0:"
    "thinking-mode=disabled:output-contract=exact-sentinel-bounded-json-object:"
    "response-format=omitted-undocumented-for-exact-model:tools=omitted:"
    f"json-start={NVIDIA_JSON_START_SENTINEL}:json-end={NVIDIA_JSON_END_SENTINEL}:"
    f"max-json-bytes={NVIDIA_MAX_BOUNDED_JSON_BYTES}:"
    "new-http-attempts=30:probe-first=true"
)
NVIDIA_AUTHORITY_SHA256 = hashlib.sha256(NVIDIA_AUTHORITY_TEXT.encode("utf-8")).hexdigest()
NVIDIA_RESUME_PREDECESSOR_MANIFEST_SHA256 = (
    "007dd4dbde09738d87db34bc77ec2f5e0e85f44e50c052177b5db311ebe818f2"
)
NVIDIA_RESUME_AUTHORITY_TEXT = (
    "phase5-nvidia-rate-limit-resume-v1:provider=nvidia-nim:model=minimaxai/minimax-m3:"
    f"predecessor-authority={NVIDIA_AUTHORITY_SHA256}:"
    f"predecessor-manifest={NVIDIA_RESUME_PREDECESSOR_MANIFEST_SHA256}:"
    "source-inventory=2245b16896f273b926bae4ee60efe09c3472271642c42b8ec0a6fcc40f99df1e:"
    "validated-membership=150845a40818d1138478489988bd2f16a74c2b6a7938d733c5ab7fc27d8c04d3:"
    "remaining-membership=4376b46dfb100f38a643022d819c4e061b5da4be6ee2c3f3cb705036d559d150:"
    "validated=3:remaining=21:new-http-cap=21:concurrency=1:min-interval-seconds=60:"
    "default-cooldown-seconds=300:max-cooldown-seconds=3600:"
    "first-429=circuit-break-batch-no-retry:blind=forbidden:activation=forbidden-until-24"
)
NVIDIA_RESUME_AUTHORITY_SHA256 = hashlib.sha256(
    NVIDIA_RESUME_AUTHORITY_TEXT.encode("utf-8")
).hexdigest()
NVIDIA_SECOND_RESUME_RECONCILIATION_SHA256 = (
    "3b132a386b098934ca6bfdd16d36a18ae74ec629a6fe25e29529e220ee54e77f"
)
NVIDIA_SECOND_RESUME_VALIDATED_MEMBERSHIP_SHA256 = (
    "1fb3c99586430b7f7c4e7442ef6b4627c8e5dbaac54b2280ce72281648967d49"
)
NVIDIA_SECOND_RESUME_REMAINING_MEMBERSHIP_SHA256 = (
    "f2be8211b4bb46be30e17e1f1eee52dc3cacc7da1a4baf7c5963be9916aab20b"
)
NVIDIA_SUPERSEDED_RESUME_TERMINAL_SHA256 = (
    "3b57d1fec3c1a789ff6424f2b60f51b2491511c2c73e3d34f06ecfc9a9483516"
)
NVIDIA_SECOND_RESUME_INTERRUPTED_PLACE_ID = (
    "place:51e051dfa095668ec9f761e4dbf9ecb06f47eb9994e1b2aa2451812fb4c43a1f"
)
NVIDIA_SECOND_RESUME_AUTHORITY_TEXT = (
    "phase5-nvidia-interrupted-second-resume-v2:provider=nvidia-nim:"
    "model=minimaxai/minimax-m3:"
    f"predecessor-authority={NVIDIA_RESUME_AUTHORITY_SHA256}:"
    f"corrective-reconciliation={NVIDIA_SECOND_RESUME_RECONCILIATION_SHA256}:"
    f"base-predecessor-manifest={NVIDIA_RESUME_PREDECESSOR_MANIFEST_SHA256}:"
    f"validated-membership={NVIDIA_SECOND_RESUME_VALIDATED_MEMBERSHIP_SHA256}:"
    f"remaining-membership={NVIDIA_SECOND_RESUME_REMAINING_MEMBERSHIP_SHA256}:"
    f"unresolved-place={NVIDIA_SECOND_RESUME_INTERRUPTED_PLACE_ID}:"
    f"superseded-terminal={NVIDIA_SUPERSEDED_RESUME_TERMINAL_SHA256}:"
    "superseded-terminal-activation=forbidden:validated=13:remaining=11:"
    "consumed-attempts=14:unresolved-attempt=14:unresolved-persisted=false:"
    "unresolved-conservatively-consumed=true:new-http-cap=11:concurrency=1:"
    "min-interval-seconds=60:whole-attempt-timeout-seconds=300:"
    "first-429=circuit-break-batch-no-retry:blind=forbidden:"
    "activation=forbidden-until-24"
)
NVIDIA_SECOND_RESUME_AUTHORITY_SHA256 = hashlib.sha256(
    NVIDIA_SECOND_RESUME_AUTHORITY_TEXT.encode("utf-8")
).hexdigest()
NVIDIA_V4_PROBE_RESUME_PREDECESSOR_AUTHORITY_RECEIPT_SHA256 = (
    "272cb3d31bb4ce660e1bda85f6fdfb972f2be4701c2e1e34c5bac9a3a466d811"
)
NVIDIA_V4_PROBE_RESUME_PREDECESSOR_MANIFEST_SHA256 = (
    "2c3b2dd4d1be3159a3600cb71789206ff1b452983484d80c3b717ed09d757b64"
)
NVIDIA_V4_PROBE_RESUME_SOURCE_INVENTORY_SHA256 = (
    "2245b16896f273b926bae4ee60efe09c3472271642c42b8ec0a6fcc40f99df1e"
)
NVIDIA_V4_PROBE_RESUME_VALIDATED_MEMBERSHIP_SHA256 = (
    "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
)
NVIDIA_V4_PROBE_RESUME_REMAINING_MEMBERSHIP_SHA256 = (
    "979127c3cfd457fa0a9354acf7fd984c8d8b4d753a97c7c176ac531e0808af7a"
)
NVIDIA_V4_PROBE_RESUME_ATTEMPT_SHA256 = (
    "31951a8d0928261b3e5d88bcd8629613e662c3160af7c44d9d5c712dbfbde12b"
)
NVIDIA_V4_PROBE_RESUME_REQUEST_SHA256 = (
    "5caa5678525ae5c69a865cb89ad71d90a29b6f33bf0ddafddac49fe0a0f2aadc"
)
NVIDIA_V4_PROBE_RESUME_RESPONSE_SHA256 = (
    "a36c4649f1cae74f95f72d67baf76497313145907b0bed3e903b15c7a4744798"
)
NVIDIA_V4_PROBE_RESUME_TERMINAL_SHA256 = (
    "e26194dbe3d70468dcdeb8580e2510a720b070299bc42865206d18766057e2e2"
)
NVIDIA_V4_PROBE_RESUME_FAILURE_SHA256 = (
    "e2430c7fe0180aea83382f5caabe1c1ab09b4df7911870a049888eaf136785e5"
)
NVIDIA_V4_PROBE_RESUME_AUTHORITY_TEXT = (
    "phase5-nvidia-v4-schema-invalid-probe-resume-v1:provider=nvidia-nim:"
    "model=minimaxai/minimax-m3:"
    f"predecessor-authority={NVIDIA_AUTHORITY_SHA256}:"
    "predecessor-authority-receipt="
    f"{NVIDIA_V4_PROBE_RESUME_PREDECESSOR_AUTHORITY_RECEIPT_SHA256}:"
    f"predecessor-manifest={NVIDIA_V4_PROBE_RESUME_PREDECESSOR_MANIFEST_SHA256}:"
    f"source-inventory={NVIDIA_V4_PROBE_RESUME_SOURCE_INVENTORY_SHA256}:"
    f"validated-membership={NVIDIA_V4_PROBE_RESUME_VALIDATED_MEMBERSHIP_SHA256}:"
    f"remaining-membership={NVIDIA_V4_PROBE_RESUME_REMAINING_MEMBERSHIP_SHA256}:"
    "consumed-attempt=1:"
    f"consumed-attempt-sha256={NVIDIA_V4_PROBE_RESUME_ATTEMPT_SHA256}:"
    f"consumed-request-sha256={NVIDIA_V4_PROBE_RESUME_REQUEST_SHA256}:"
    f"consumed-response-sha256={NVIDIA_V4_PROBE_RESUME_RESPONSE_SHA256}:"
    "consumed-outcome=RESPONSE_INVALID:consumed-http-status=200:"
    f"terminal={NVIDIA_V4_PROBE_RESUME_TERMINAL_SHA256}:"
    f"failure={NVIDIA_V4_PROBE_RESUME_FAILURE_SHA256}:"
    "validated=0:remaining=24:new-http-cap=29:attempts-start=2:concurrency=1:"
    "min-interval-seconds=60:whole-attempt-timeout-seconds=300:"
    "first-429=circuit-break-batch-no-retry:invalid-probe=no-replay:"
    "blind=forbidden:activation=forbidden-until-24"
)
NVIDIA_V4_PROBE_RESUME_AUTHORITY_SHA256 = hashlib.sha256(
    NVIDIA_V4_PROBE_RESUME_AUTHORITY_TEXT.encode("utf-8")
).hexdigest()
NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS: Mapping[str, str] = {
    "prompt_contract_commit": "00260595c7ed90cf34a6fbef219c40155fe23abe",
    "prompt_version": "phase5-demo-profile-sentinel-json.v5",
    "prompt_sha256": "aaa0328deaae58999b96eb9a43f176e589eb95319c3a80e9cd2978b23b925b3a",
    "v4_request_manifest_sha256": (
        "3d7a9e867febdba88f68794a4185f1db29450c0ac1718d7402aa7b39553bded0"
    ),
    "v5_request_manifest_sha256": (
        "fe0179b3f316ca5b6f5805052559a17756cac555bbd273d98b1324e9e9c3225e"
    ),
    "schema_example_manifest_sha256": (
        "d9d716942af28a5ac2bacc647112576b03f32f0a07c132b07b752ec95a687852"
    ),
    "probe_place_id": ("place:01ffd19d7d710b9197a37689a65f8d10214be68ff31cf947ebf5b3251a274015"),
    "probe_v4_request_sha256": ("e705cd32db494530b4f66c0c1033f19a518fca99b2c49cb3e51533e76b305dfd"),
    "probe_v5_request_sha256": ("d5046ee8f0433cd7d63be7c0b6030c79e73e27aba8e9147075b49495ef8b4e83"),
    "source_inventory_sha256": NVIDIA_V4_PROBE_RESUME_SOURCE_INVENTORY_SHA256,
    "validated_membership_sha256": NVIDIA_V4_PROBE_RESUME_VALIDATED_MEMBERSHIP_SHA256,
    "remaining_membership_sha256": NVIDIA_V4_PROBE_RESUME_REMAINING_MEMBERSHIP_SHA256,
    "attempt1_authority_sha256": NVIDIA_AUTHORITY_SHA256,
    "attempt1_authority_receipt_sha256": (
        NVIDIA_V4_PROBE_RESUME_PREDECESSOR_AUTHORITY_RECEIPT_SHA256
    ),
    "attempt1_root_manifest_sha256": NVIDIA_V4_PROBE_RESUME_PREDECESSOR_MANIFEST_SHA256,
    "attempt1_authority_file_sha256": (
        "32a2e2724514f8b2e54446cf2c69142fdc6673ae988eae0022ec291a95244915"
    ),
    "attempt1_reservation_sha256": (
        "22d20ca243644543007ee3b3c8d9e48d385536ac90ed7ed83b1f44c3bfd7a206"
    ),
    "attempt1_reservation_file_sha256": (
        "c1d07da7afe47789d48e9a55fa2eaf4d11773c72f27003a713f14ae3bdc6effd"
    ),
    "attempt1_attempt_sha256": NVIDIA_V4_PROBE_RESUME_ATTEMPT_SHA256,
    "attempt1_attempt_file_sha256": (
        "e4b49689c1cc1fcfe20f721e1aa8e8f0461f6fb951c437c7c0d6c438f9a39dcd"
    ),
    "attempt1_journal_sha256": ("efcce9b437b6b4c5da5ba5ac90849e7e76849392d7539e2bedad878515eb5d39"),
    "attempt1_contract_request_sha256": NVIDIA_V4_PROBE_RESUME_REQUEST_SHA256,
    "attempt1_http_request_sha256": (
        "e705cd32db494530b4f66c0c1033f19a518fca99b2c49cb3e51533e76b305dfd"
    ),
    "attempt1_response_sha256": NVIDIA_V4_PROBE_RESUME_RESPONSE_SHA256,
    "attempt1_terminal_sha256": NVIDIA_V4_PROBE_RESUME_TERMINAL_SHA256,
    "attempt1_terminal_file_sha256": (
        "3aa5ba7c0b2b8ef937d3c9c935c1aff2017394e6ef8135357dbe27b9b1b0667b"
    ),
    "attempt1_failure_sha256": NVIDIA_V4_PROBE_RESUME_FAILURE_SHA256,
    "attempt1_failure_manifest_sha256": (
        "4c6250ddac5b4a7394ff49f95a0258632dc0cc6e86995adb232a346c2585a1b0"
    ),
    "attempt1_failure_file_sha256": (
        "3fa1892153adfe78ee67281aeb240b0e34d6227be9f16d0b291fecb9c31ea776"
    ),
    "attempt2_authority_sha256": NVIDIA_V4_PROBE_RESUME_AUTHORITY_SHA256,
    "attempt2_authority_receipt_sha256": (
        "40b0de4d9775660e897d805aa7d4d45eed769bcd8cffeca566c7d283d4fa272c"
    ),
    "attempt2_root_manifest_sha256": (
        "be6c2bec5db91e08d54cc20974e1e604363b116c35f9e5d60da7af61a5801b17"
    ),
    "attempt2_authority_file_sha256": (
        "27c8d82dc96df0272494114665c8d32f04f861801aa029885436b997bc6dab8b"
    ),
    "attempt2_reservation_sha256": (
        "506b50f0ac00774aad23ee1ac516139457e955f8bccae58a9e50b435e4fda87b"
    ),
    "attempt2_reservation_file_sha256": (
        "bc54f81b50dcf803fe375efa38588330ea3bed8648fed1c02ced77c9299af95d"
    ),
    "attempt2_attempt_sha256": ("60266facd4cd0cacebd7b9ec161c5990e05185af7cd77e2578ed0300827a3a9d"),
    "attempt2_attempt_file_sha256": (
        "8521928e5147fb66ac62769b311e0dd3115343f8acd8bd2faf1330ccaa4b8ac9"
    ),
    "attempt2_journal_sha256": ("333c1d8aa5d81e0fae7c7a11c22508434b8f0546fb0f0044e39f8e0989576cc3"),
    "attempt2_contract_request_sha256": NVIDIA_V4_PROBE_RESUME_REQUEST_SHA256,
    "attempt2_http_request_sha256": (
        "e705cd32db494530b4f66c0c1033f19a518fca99b2c49cb3e51533e76b305dfd"
    ),
    "attempt2_response_sha256": (
        "0672a656dccbd0dffc75a1e32a28f7126d5b351d6285c815656ab1f2a44956fc"
    ),
    "attempt2_terminal_sha256": (
        "145cfbe7e68745ab642607d934e57d90da22c107eef9eb352b70140a275bea17"
    ),
    "attempt2_terminal_file_sha256": (
        "4a5f39fee7e85366e42e8ab489a7e83896ce415239c6104fbb0ad5309ba7e241"
    ),
    "attempt2_failure_sha256": ("555d8aaccbaa0dcb49e506cf7f20d5d8608999cde2e37ae4fe118dc3db312e66"),
    "attempt2_failure_manifest_sha256": (
        "061e9b0527c0bba9a7c5261c42e508ca5bc8f6e1ed7cd9300c2a13501ea8b68f"
    ),
    "attempt2_failure_file_sha256": (
        "5e3c9acad3fbe29600546541b510706b0cee2980c2c9a4f40e948f728fd8e2a7"
    ),
}
NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_TEXT = (
    "phase5-nvidia-v5-two-schema-invalid-probe-resume-v1:provider=nvidia-nim:model=minima"
    "xai/minimax-m3:endpoint=https://integrate.api.nvidia.com/v1/chat/completions:prompt-"
    "contract-commit=00260595c7ed90cf34a6fbef219c40155fe23abe:prompt-version=phase5-demo-"
    "profile-sentinel-json.v5:prompt-sha256=aaa0328deaae58999b96eb9a43f176e589eb95319c3a8"
    "0e9cd2978b23b925b3a:request-contract=EXACT_COMPLETE_EXAMPLE_V1:predecessor-prompt-ve"
    "rsion=phase5-demo-profile-sentinel-json.v4:v4-request-manifest=3d7a9e867febdba88f687"
    "94a4185f1db29450c0ac1718d7402aa7b39553bded0:v5-request-manifest=fe0179b3f316ca5b6f58"
    "05052559a17756cac555bbd273d98b1324e9e9c3225e:schema-example-manifest=d9d716942af28a5"
    "ac2bacc647112576b03f32f0a07c132b07b752ec95a687852:probe-place=place:01ffd19d7d710b91"
    "97a37689a65f8d10214be68ff31cf947ebf5b3251a274015:probe-v4-request=e705cd32db494530b4"
    "f66c0c1033f19a518fca99b2c49cb3e51533e76b305dfd:probe-v5-request=d5046ee8f0433cd7d63b"
    "e7c0b6030c79e73e27aba8e9147075b49495ef8b4e83:source-inventory=2245b16896f273b926bae4"
    "ee60efe09c3472271642c42b8ec0a6fcc40f99df1e:validated-membership=4f53cda18c2baa0c0354"
    "bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945:remaining-membership=979127c3cfd457fa0a"
    "9354acf7fd984c8d8b4d753a97c7c176ac531e0808af7a:attempt1-authority=eb8ae4a76babea5012"
    "eeccc49e6484deabda17c373ddb3d55167f3bdda1277f2:attempt1-authority-receipt=272cb3d31b"
    "b4ce660e1bda85f6fdfb972f2be4701c2e1e34c5bac9a3a466d811:attempt1-root-manifest=2c3b2d"
    "d4d1be3159a3600cb71789206ff1b452983484d80c3b717ed09d757b64:attempt1-authority-file=3"
    "2a2e2724514f8b2e54446cf2c69142fdc6673ae988eae0022ec291a95244915:attempt1-reservation"
    "-self=22d20ca243644543007ee3b3c8d9e48d385536ac90ed7ed83b1f44c3bfd7a206:attempt1-rese"
    "rvation-file=c1d07da7afe47789d48e9a55fa2eaf4d11773c72f27003a713f14ae3bdc6effd:attemp"
    "t1-attempt-self=31951a8d0928261b3e5d88bcd8629613e662c3160af7c44d9d5c712dbfbde12b:att"
    "empt1-attempt-file=e4b49689c1cc1fcfe20f721e1aa8e8f0461f6fb951c437c7c0d6c438f9a39dcd:"
    "attempt1-journal=efcce9b437b6b4c5da5ba5ac90849e7e76849392d7539e2bedad878515eb5d39:at"
    "tempt1-contract-request=5caa5678525ae5c69a865cb89ad71d90a29b6f33bf0ddafddac49fe0a0f2"
    "aadc:attempt1-http-request=e705cd32db494530b4f66c0c1033f19a518fca99b2c49cb3e51533e76"
    "b305dfd:attempt1-response=a36c4649f1cae74f95f72d67baf76497313145907b0bed3e903b15c7a4"
    "744798:attempt1-terminal-self=e26194dbe3d70468dcdeb8580e2510a720b070299bc42865206d18"
    "766057e2e2:attempt1-terminal-file=3aa5ba7c0b2b8ef937d3c9c935c1aff2017394e6ef8135357d"
    "be27b9b1b0667b:attempt1-failure-self=e2430c7fe0180aea83382f5caabe1c1ab09b4df7911870a"
    "049888eaf136785e5:attempt1-failure-manifest=4c6250ddac5b4a7394ff49f95a0258632dc0cc6e"
    "86995adb232a346c2585a1b0:attempt1-failure-file=3fa1892153adfe78ee67281aeb240b0e34d62"
    "27be9f16d0b291fecb9c31ea776:attempt1-outcome=RESPONSE_INVALID:attempt1-http-status=2"
    "00:attempt2-authority=d35af02c8865a2f03561bd52024c6934bf39373298ea9def54d3c55c2f1cce"
    "7e:attempt2-authority-receipt=40b0de4d9775660e897d805aa7d4d45eed769bcd8cffeca566c7d2"
    "83d4fa272c:attempt2-root-manifest=be6c2bec5db91e08d54cc20974e1e604363b116c35f9e5d60d"
    "a7af61a5801b17:attempt2-authority-file=27c8d82dc96df0272494114665c8d32f04f861801aa02"
    "9885436b997bc6dab8b:attempt2-reservation-self=506b50f0ac00774aad23ee1ac516139457e955"
    "f8bccae58a9e50b435e4fda87b:attempt2-reservation-file=bc54f81b50dcf803fe375efa3858833"
    "0ea3bed8648fed1c02ced77c9299af95d:attempt2-attempt-self=60266facd4cd0cacebd7b9ec161c"
    "5990e05185af7cd77e2578ed0300827a3a9d:attempt2-attempt-file=8521928e5147fb66ac62769b3"
    "11e0dd3115343f8acd8bd2faf1330ccaa4b8ac9:attempt2-journal=333c1d8aa5d81e0fae7c7a11c22"
    "508434b8f0546fb0f0044e39f8e0989576cc3:attempt2-contract-request=5caa5678525ae5c69a86"
    "5cb89ad71d90a29b6f33bf0ddafddac49fe0a0f2aadc:attempt2-http-request=e705cd32db494530b"
    "4f66c0c1033f19a518fca99b2c49cb3e51533e76b305dfd:attempt2-response=0672a656dccbd0dffc"
    "75a1e32a28f7126d5b351d6285c815656ab1f2a44956fc:attempt2-terminal-self=145cfbe7e68745"
    "ab642607d934e57d90da22c107eef9eb352b70140a275bea17:attempt2-terminal-file=4a5f39fee7"
    "e85366e42e8ab489a7e83896ce415239c6104fbb0ad5309ba7e241:attempt2-failure-self=555d8aa"
    "ccbaa0dcb49e506cf7f20d5d8608999cde2e37ae4fe118dc3db312e66:attempt2-failure-manifest="
    "061e9b0527c0bba9a7c5261c42e508ca5bc8f6e1ed7cd9300c2a13501ea8b68f:attempt2-failure-fi"
    "le=5e3c9acad3fbe29600546541b510706b0cee2980c2c9a4f40e948f728fd8e2a7:attempt2-outcome"
    "=RESPONSE_INVALID:attempt2-http-status=200:validated=0:remaining=24:consumed-http-at"
    "tempts=2:cumulative-http-cap=30:new-http-cap=28:attempts-start=3:concurrency=1:min-i"
    "nterval-seconds=60:whole-attempt-timeout-seconds=300:temperature=0:top-p=omitted-pro"
    "vider-default-0.95:max-tokens=8192:seed=0:thinking-mode=disabled:output-contract=exa"
    "ct-sentinel-bounded-json-object-with-complete-example:response-format=omitted-undocu"
    "mented-for-exact-model:tools=omitted:json-start=<<<ITDA_PROFILE_JSON_V3_START_4F3A6C"
    "91>>>:json-end=<<<ITDA_PROFILE_JSON_V3_END_9B7D2E65>>>:max-json-bytes=65536:first-42"
    "9=circuit-break-batch-no-retry:invalid-probes=no-replay:profile-lineage=v5-required-"
    "no-v4-masquerade:blind=forbidden:generation=forbidden-until-24-current-valid-v5:acti"
    "vation=forbidden-until-24:single-live-invocation=true"
)
NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_SHA256 = hashlib.sha256(
    NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_TEXT.encode("utf-8")
).hexdigest()
NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_TEXT = (
    "phase5-nvidia-v5-three-validated-terminal-invalid-resume-v1:provider=nvidia-nim:model=minimaxai/"
    "minimax-m3:endpoint=https://integrate.api.nvidia.com/v1/chat/completions:prompt-contract-commit="
    "00260595c7ed90cf34a6fbef219c40155fe23abe:predecessor-implementation-commit=2626fe6bf484f2bfbf219"
    "50be14ec42b1c97ef1b:prompt-version=phase5-demo-profile-sentinel-json.v5:prompt-sha256=aaa0328dea"
    "ae58999b96eb9a43f176e589eb95319c3a80e9cd2978b23b925b3a:request-contract=EXACT_COMPLETE_EXAMPLE_V"
    "1:source-inventory=2245b16896f273b926bae4ee60efe09c3472271642c42b8ec0a6fcc40f99df1e:all-dev-v5-r"
    "equest-manifest=fe0179b3f316ca5b6f5805052559a17756cac555bbd273d98b1324e9e9c3225e:all-dev-schema-"
    "example-manifest=d9d716942af28a5ac2bacc647112576b03f32f0a07c132b07b752ec95a687852:remaining-v5-r"
    "equest-manifest=6be9d7ab3d54430bb88e53e5b21e54d80f6db0798078dad90875a36b3411bf8f:remaining-schem"
    "a-example-manifest=958cf03e919bc76654a256c2e56a05770ac986f3dac4e9d37f1304a2c4252c92:predecessor-"
    "resume-authority=2d6067aa3eb3c03ad419ab915e16ebda43a9524d5ed2eeb767556259efccd170:predecessor-au"
    "thority-receipt=12c350a257ab6326949f35938dbed9d104557cb812bf700947891e3f1823f6a9:predecessor-roo"
    "t-manifest=a89142fa7ec21e5f862d361c0ac82a0df0cc31e1b8f4f99aff469687258804e0:predecessor-authorit"
    "y-file=0def638830d74575a488388d699a774f9d6af3295a8fa30491421ff29c3e6b62:attempt1-place=place:01f"
    "fd19d7d710b9197a37689a65f8d10214be68ff31cf947ebf5b3251a274015:attempt1-lineage-authority=eb8ae4a"
    "76babea5012eeccc49e6484deabda17c373ddb3d55167f3bdda1277f2:attempt1-root-manifest=2c3b2dd4d1be315"
    "9a3600cb71789206ff1b452983484d80c3b717ed09d757b64:attempt1-attempt-self=31951a8d0928261b3e5d88bc"
    "d8629613e662c3160af7c44d9d5c712dbfbde12b:attempt1-attempt-file=e4b49689c1cc1fcfe20f721e1aa8e8f04"
    "61f6fb951c437c7c0d6c438f9a39dcd:attempt1-journal=efcce9b437b6b4c5da5ba5ac90849e7e76849392d7539e2"
    "bedad878515eb5d39:attempt1-contract-request=5caa5678525ae5c69a865cb89ad71d90a29b6f33bf0ddafddac4"
    "9fe0a0f2aadc:attempt1-http-request=e705cd32db494530b4f66c0c1033f19a518fca99b2c49cb3e51533e76b305"
    "dfd:attempt1-response=a36c4649f1cae74f95f72d67baf76497313145907b0bed3e903b15c7a4744798:attempt1-"
    "outcome=RESPONSE_INVALID:attempt1-http-status=200:attempt1-terminal-self=e26194dbe3d70468dcdeb85"
    "80e2510a720b070299bc42865206d18766057e2e2:attempt1-terminal-file=3aa5ba7c0b2b8ef937d3c9c935c1aff"
    "2017394e6ef8135357dbe27b9b1b0667b:attempt1-failure-self=e2430c7fe0180aea83382f5caabe1c1ab09b4df7"
    "911870a049888eaf136785e5:attempt1-failure-manifest=4c6250ddac5b4a7394ff49f95a0258632dc0cc6e86995"
    "adb232a346c2585a1b0:attempt1-failure-file=3fa1892153adfe78ee67281aeb240b0e34d6227be9f16d0b291fec"
    "b9c31ea776:attempt2-place=place:01ffd19d7d710b9197a37689a65f8d10214be68ff31cf947ebf5b3251a274015"
    ":attempt2-lineage-authority=d35af02c8865a2f03561bd52024c6934bf39373298ea9def54d3c55c2f1cce7e:att"
    "empt2-root-manifest=be6c2bec5db91e08d54cc20974e1e604363b116c35f9e5d60da7af61a5801b17:attempt2-at"
    "tempt-self=60266facd4cd0cacebd7b9ec161c5990e05185af7cd77e2578ed0300827a3a9d:attempt2-attempt-fil"
    "e=8521928e5147fb66ac62769b311e0dd3115343f8acd8bd2faf1330ccaa4b8ac9:attempt2-journal=333c1d8aa5d8"
    "1e0fae7c7a11c22508434b8f0546fb0f0044e39f8e0989576cc3:attempt2-contract-request=5caa5678525ae5c69"
    "a865cb89ad71d90a29b6f33bf0ddafddac49fe0a0f2aadc:attempt2-http-request=e705cd32db494530b4f66c0c10"
    "33f19a518fca99b2c49cb3e51533e76b305dfd:attempt2-response=0672a656dccbd0dffc75a1e32a28f7126d5b351"
    "d6285c815656ab1f2a44956fc:attempt2-outcome=RESPONSE_INVALID:attempt2-http-status=200:attempt2-te"
    "rminal-self=145cfbe7e68745ab642607d934e57d90da22c107eef9eb352b70140a275bea17:attempt2-terminal-f"
    "ile=4a5f39fee7e85366e42e8ab489a7e83896ce415239c6104fbb0ad5309ba7e241:attempt2-failure-self=555d8"
    "aaccbaa0dcb49e506cf7f20d5d8608999cde2e37ae4fe118dc3db312e66:attempt2-failure-manifest=061e9b0527"
    "c0bba9a7c5261c42e508ca5bc8f6e1ed7cd9300c2a13501ea8b68f:attempt2-failure-file=5e3c9acad3fbe296005"
    "46541b510706b0cee2980c2c9a4f40e948f728fd8e2a7:attempt3-place=place:01ffd19d7d710b9197a37689a65f8"
    "d10214be68ff31cf947ebf5b3251a274015:attempt3-lineage-authority=2d6067aa3eb3c03ad419ab915e16ebda4"
    "3a9524d5ed2eeb767556259efccd170:attempt3-reservation-self=355ce5f88be38a1aa382ee5d8b6414401214de"
    "35ca436df858756d77e13f1706:attempt3-reservation-file=acbf4e8c2bd2062b0a3277accd07bcc00df4edefa2d"
    "8f4ff0f257c0ceb4d6db1:attempt3-attempt-self=2871b6d1967c8b910855a1d583adf4d915aa518a4d6b2a3382a2"
    "82bce7aedc63:attempt3-attempt-file=52876de2e5b492c8e62fc47a0cef37b07d2b1ffea45c434a524c0fd6d5779"
    "a95:attempt3-journal=e5fa4eec68f14b8fe303975f35f7a3a3f324842af6efaeffe0cf8aba80376894:attempt3-c"
    "ontract-request=3f8ba29065922d51bb7592bc0e7402f2c4370a0784b816482232cc13bf81bb49:attempt3-http-r"
    "equest=d5046ee8f0433cd7d63be7c0b6030c79e73e27aba8e9147075b49495ef8b4e83:attempt3-response=4c662d"
    "2992cfef894291152d819212057b1ceba5ec175699f181f4ebe2a4f154:attempt3-outcome=VALIDATED:attempt3-h"
    "ttp-status=200:attempt3-error-code=none:attempt3-retry=false:attempt3-profile=ceea4848bc038b33ae"
    "4fa3fea46a6d5b28ce18f9a70d18faaa5689c6f33cb9f6:attempt4-place=place:028ea3b319c4d0a45d0031d3f2aa"
    "78dfe0b40d272eb637fceaecdba10aff1a4a:attempt4-lineage-authority=2d6067aa3eb3c03ad419ab915e16ebda"
    "43a9524d5ed2eeb767556259efccd170:attempt4-reservation-self=ff1a3fc5e8da0d6c2f8a967b491c9f643655c"
    "f08bff3c8ceab50179373aff6f1:attempt4-reservation-file=a466b18e4f4eff5956dd1f2e2805ed7c93f09bbf31"
    "9218328da8cab5299ca8e9:attempt4-attempt-self=3cdd40d2c9615d8d833f2c17e70772d78d0493eed4a20774d2d"
    "45b8645a529c7:attempt4-attempt-file=dc8140364c626431bb15df96a7339d8af207254cc92a2ac9f72bd79b34a4"
    "0274:attempt4-journal=99fc39656eea72869939e8c5a1c691906c468788f8cd8e661272bf7604d1f5c4:attempt4-"
    "contract-request=4c081bb9bc9145242dd8796aace7fa4822b6a488ce44e516131ffdb423d1bcaf:attempt4-http-"
    "request=c413f52cfe2800e66800f7e06e0a7028208ad13c07ec91daf80e3a6b86ca748f:attempt4-response=17be0"
    "c4a166b295b18dd81be37a529e9b8bc8d6303bda62f44d8f16de3c94311:attempt4-outcome=VALIDATED:attempt4-"
    "http-status=200:attempt4-error-code=none:attempt4-retry=false:attempt4-profile=1b42e24e559cf3b41"
    "64c0ae7929405b150af8341764d0b159262ae88ee184076:attempt5-place=place:119da6ea8756c8731f65f3fae9c"
    "5553ac16c8317f6688a68013cf3ead04916d8:attempt5-lineage-authority=2d6067aa3eb3c03ad419ab915e16ebd"
    "a43a9524d5ed2eeb767556259efccd170:attempt5-reservation-self=db22f2320ee5d3d31bbccd8c46db9518fe24"
    "dc51483a4ee7bfd62e74de68d758:attempt5-reservation-file=c283ff8b4f3f9927f6d86d18a95f31bb0bfc1cb90"
    "ed70f3d0b4a5c2d57bb3363:attempt5-attempt-self=7196ea968459e5adda5b5189708728ac96b4f870cd852508ef"
    "46b949eea8ea8b:attempt5-attempt-file=9b1aedd28121de79413c6cd8a4427ede9f796e6ec4987b250974a207373"
    "48b5f:attempt5-journal=0e38976ca16954f45e4b2d682a9d25b3ebd04021210e1824f181ef9d69222d83:attempt5"
    "-contract-request=945fbfb904560eef36befe54574c0cccba101c335f22524fae3461a560487d23:attempt5-http"
    "-request=727c024e0df6ee0714e28783facacb552d88e6af80955b24a829427a6dfdfde2:attempt5-response=6922"
    "b37d5f73590e437df5a9b802584b736382c72f9f6183736ec2cd64fad29f:attempt5-outcome=VALIDATED:attempt5"
    "-http-status=200:attempt5-error-code=none:attempt5-retry=false:attempt5-profile=4feff1d3e1c1bc72"
    "7c6511d879706b0fbace2527c731d5e6df5580590f5596ae:attempt6-place=place:1382768797abf757779da08f8a"
    "d806b8403ffb3f400dab9c91446e368c024f4b:attempt6-lineage-authority=2d6067aa3eb3c03ad419ab915e16eb"
    "da43a9524d5ed2eeb767556259efccd170:attempt6-reservation-self=5c466ac0e82f2542c6a1ff928db76d5658c"
    "882d93d14257f70945b5d3a92b248:attempt6-reservation-file=f8355b90d433a1c78bbd4ff8abff0bea8cc0050f"
    "d1178dfb08198bf5c1113e83:attempt6-attempt-self=b978308d8605d581f83861644b63cd8b16d148b4c42a4b897"
    "f959dc61be51be8:attempt6-attempt-file=9e964ccb6889de55a8de5c9c23788ff60423d9fd5b06adbbaad7163ee5"
    "b3a716:attempt6-journal=82895bce0e2829db9fa71f1ba56540e24e0b31ade2ba49a86cd925e8f53b76a5:attempt"
    "6-contract-request=48a706dcddfd974953fc6d64dfed8acb202a2aac2498c446d45df127f00d3bc3:attempt6-htt"
    "p-request=ac8302059f9cdf24a956a1077b4eec20c74d37670b183a491100ca4828a90cb5:attempt6-response=d80"
    "5415abe66787220a2eabaaf865f8750d0235358485a790b51d7edffb8b876:attempt6-outcome=RESPONSE_INVALID:"
    "attempt6-http-status=200:attempt6-error-code=PROVIDER_RESPONSE_TERMINAL_INVALID:attempt6-retry=f"
    "alse:attempt6-terminal-self=5c14a3e2f9679f9ad8de0af4c579835dfa2ae8265b2d3f88fedcbb2b0fc7cbb7:att"
    "empt6-terminal-file=dfe448ebf5ab3614f6cb25631f07620c68e951ecdd9db87b6d833fc0cb6d4862:attempt6-fa"
    "ilure-self=a11f3dad30d6fac9be72a3f1efe9073a204b2bc55eaee3f6551afc37c4d95f41:attempt6-failure-fil"
    "e=757655484d36e64cadf0a48f2da4cebd2cec7bc350632b5bd0e01ec7e939d849:attempt6-failure-manifest=7b2"
    "ca9d2f318352f6e8e7340962783122c759e5895c04248546eeea6f8de7cd3:attempt6-failure-attempts-file=61c"
    "852d06259ca30f7b47fc82e3974dfa9b6ced1e1002e6f559336fd611815dd:attempt6-response-disposition=immu"
    "table-invalid-no-profile-no-raw-replay:attempt6-publishable=false:consumed-attempt-manifest=c6eb"
    "72df0c85764ca0674868e41e09dbeacf08ff5c773c6b43b642d636e87e8e:consumed-http-attempts=6:validated-"
    "attempts=3,4,5:validated=3:validated-place-ids=place:01ffd19d7d710b9197a37689a65f8d10214be68ff31"
    "cf947ebf5b3251a274015,place:028ea3b319c4d0a45d0031d3f2aa78dfe0b40d272eb637fceaecdba10aff1a4a,pla"
    "ce:119da6ea8756c8731f65f3fae9c5553ac16c8317f6688a68013cf3ead04916d8:validated-membership=150845a"
    "40818d1138478489988bd2f16a74c2b6a7938d733c5ab7fc27d8c04d3:validated-profile-sha256=ceea4848bc038"
    "b33ae4fa3fea46a6d5b28ce18f9a70d18faaa5689c6f33cb9f6,1b42e24e559cf3b4164c0ae7929405b150af8341764d"
    "0b159262ae88ee184076,4feff1d3e1c1bc727c6511d879706b0fbace2527c731d5e6df5580590f5596ae:validated-"
    "profile-manifest=abcff5db145431d6bdce9ce8f1ca60cf124caa914e7498313c7465f79c060823:profile-replay"
    "-created-at-policy=attempt-started-at-utc:remaining=21:remaining-place-ids=place:1382768797abf75"
    "7779da08f8ad806b8403ffb3f400dab9c91446e368c024f4b,place:13e97270ee89f51469e4351a78e78667cb280a79"
    "bfff31b09e79dbcf5657cb3d,place:2d9350874386a80df162df9a81d99c27dd3daee94eafb8685c410ac37bd33f22,"
    "place:2e45cd43f9ada5f923bf702baa120595da9b1a4a1205f217e05e00dfc403dc18,place:2ee63c737daf239718e"
    "16ee2a53222db886be3f7d9c345a2ed4e7c8ad02536a0,place:33515ac990a21f3fd8980f963625adcf6bc95eedf826"
    "625c7124d9c44eaade19,place:342fbc04c8c21313b3229ab32d84bdd111efb76bd029c00c962a836d9807339f,plac"
    "e:4028f3f38d5ccdd7f97a4c80a21f3416a40fd387d7e4d630b2884c640f01ccc3,place:4b57cdef6b3930b551b3e51"
    "f98bd4e6f79be8c79ea2d0b74a2b5b57c65c690c0,place:50723a8c5ce99fa340e205db0cabd5a68e649a2e461ee4fd"
    "3b6ff8b7f7ca3f59,place:51e051dfa095668ec9f761e4dbf9ecb06f47eb9994e1b2aa2451812fb4c43a1f,place:55"
    "f2606ec1c3c53f6742537bc95bb1a3c7951ca92254eaf0aa9a164033908326,place:575b356185f8edd4b35d564c990"
    "d9dc04392c80e3bebf8dd967c77fe7f15b1b2,place:86781b603cb2264558c59743bc4422e63c6224cb971e467ebeed"
    "72f304e423de,place:88364b595917974034901067047d4b3c6c4bf54f0aaa9390284a587fdf690528,place:aa92b3"
    "6a3a70b499f58c65ed2f3c26908a23c631824bd811ecb6f523ebdc0c44,place:cc228be94470e9b7330d88b4e756db1"
    "70fec5e90e3364e77ff86826a32455ccd,place:ce7793c3d7c6e0abac98a091248e2609ea3e3275e92c874e916abd43"
    "7156726a,place:cf5037785cc1b065f66890410c07ed0013f9148c302faef609b91922161fbba4,place:d18e2ecf50"
    "dfb21415191c28a18badafc767ff17d8feddc91b7e0b54f506d40d,place:f662d1bd7b4626d1b80f64cf0409a4674b1"
    "363f783a0d79ed2e8f23327584323:remaining-membership=4376b46dfb100f38a643022d819c4e061b5da4be6ee2c"
    "3f3cb705036d559d150:membership-canonicalization=ordered-dev24-minus-validated-v1:attempts-start="
    "7:cumulative-http-cap=30:cumulative-http-remaining=24:new-http-cap=24:future-place-request-count"
    "=21:concurrency=1:min-interval-seconds=60:whole-attempt-timeout-seconds=300:temperature=0:top-p="
    "omitted-provider-default-0.95:max-tokens=8192:seed=0:thinking-mode=disabled:output-contract=exac"
    "t-sentinel-bounded-json-object-with-complete-example:response-format=omitted-undocumented-for-ex"
    "act-model:tools=omitted:json-start=<<<ITDA_PROFILE_JSON_V3_START_4F3A6C91>>>:json-end=<<<ITDA_PR"
    "OFILE_JSON_V3_END_9B7D2E65>>>:max-json-bytes=65536:first-429=circuit-break-batch-no-retry:termin"
    "al-invalid=circuit-break-batch-no-retry:invalid-attempts=1,2,6-no-replay:validated-attempts-poli"
    "cy=3,4,5-local-replay-only-no-http:profile-lineage=v5-required-no-v4-masquerade:blind=forbidden:"
    "generation=forbidden-until-exact-24-current-valid-v5:activation=forbidden-until-exact-24:single-"
    "future-live-invocation=true:derivation-only-until-explicit-execution-approval=true:historical-ge"
    "neration=4354deace22c92a821f7ada3ff307dff775736fa7a9618a2eab3b2a29bc96581:historical-release=59c"
    "3a6379e1e3de6ef67d95947d80f39d97c21bdcbf368d0080e5d8aa7224c50:active-pointer-file=9c3d28fb770b3c"
    "8b53acee419abdefe1fed21fb14d2854c9f2f5fd685566d0fc"
)
NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_SHA256 = hashlib.sha256(
    NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_TEXT.encode("utf-8")
).hexdigest()
NVIDIA_V5_THREE_VALIDATED_RESUME_BINDINGS: Mapping[str, object] = {
    "source_inventory_sha256": NVIDIA_V4_PROBE_RESUME_SOURCE_INVENTORY_SHA256,
    "prompt_version": "phase5-demo-profile-sentinel-json.v5",
    "prompt_sha256": NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS["prompt_sha256"],
    "predecessor_authority_sha256": NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_SHA256,
    "predecessor_authority_receipt_sha256": (
        "12c350a257ab6326949f35938dbed9d104557cb812bf700947891e3f1823f6a9"
    ),
    "predecessor_root_manifest_sha256": (
        "a89142fa7ec21e5f862d361c0ac82a0df0cc31e1b8f4f99aff469687258804e0"
    ),
    "predecessor_authority_file_sha256": (
        "0def638830d74575a488388d699a774f9d6af3295a8fa30491421ff29c3e6b62"
    ),
    "failure_sha256": "a11f3dad30d6fac9be72a3f1efe9073a204b2bc55eaee3f6551afc37c4d95f41",
    "failure_file_sha256": ("757655484d36e64cadf0a48f2da4cebd2cec7bc350632b5bd0e01ec7e939d849"),
    "failure_manifest_sha256": ("7b2ca9d2f318352f6e8e7340962783122c759e5895c04248546eeea6f8de7cd3"),
    "failure_attempts_file_sha256": (
        "61c852d06259ca30f7b47fc82e3974dfa9b6ced1e1002e6f559336fd611815dd"
    ),
    "validated_attempt_numbers": (3, 4, 5),
    "terminal_invalid_attempt_numbers": (1, 2, 6),
    "validated_place_ids": (
        "place:01ffd19d7d710b9197a37689a65f8d10214be68ff31cf947ebf5b3251a274015",
        "place:028ea3b319c4d0a45d0031d3f2aa78dfe0b40d272eb637fceaecdba10aff1a4a",
        "place:119da6ea8756c8731f65f3fae9c5553ac16c8317f6688a68013cf3ead04916d8",
    ),
    "validated_profile_sha256": (
        "ceea4848bc038b33ae4fa3fea46a6d5b28ce18f9a70d18faaa5689c6f33cb9f6",
        "1b42e24e559cf3b4164c0ae7929405b150af8341764d0b159262ae88ee184076",
        "4feff1d3e1c1bc727c6511d879706b0fbace2527c731d5e6df5580590f5596ae",
    ),
    "validated_membership_sha256": (
        "150845a40818d1138478489988bd2f16a74c2b6a7938d733c5ab7fc27d8c04d3"
    ),
    "validated_profile_manifest_sha256": (
        "abcff5db145431d6bdce9ce8f1ca60cf124caa914e7498313c7465f79c060823"
    ),
    "remaining_membership_sha256": (
        "4376b46dfb100f38a643022d819c4e061b5da4be6ee2c3f3cb705036d559d150"
    ),
    "all_v5_request_manifest_sha256": (
        "fe0179b3f316ca5b6f5805052559a17756cac555bbd273d98b1324e9e9c3225e"
    ),
    "all_schema_example_manifest_sha256": (
        "d9d716942af28a5ac2bacc647112576b03f32f0a07c132b07b752ec95a687852"
    ),
    "remaining_v5_request_manifest_sha256": (
        "6be9d7ab3d54430bb88e53e5b21e54d80f6db0798078dad90875a36b3411bf8f"
    ),
    "remaining_schema_example_manifest_sha256": (
        "958cf03e919bc76654a256c2e56a05770ac986f3dac4e9d37f1304a2c4252c92"
    ),
    "terminal_sha256": "5c14a3e2f9679f9ad8de0af4c579835dfa2ae8265b2d3f88fedcbb2b0fc7cbb7",
    "terminal_file_sha256": ("dfe448ebf5ab3614f6cb25631f07620c68e951ecdd9db87b6d833fc0cb6d4862"),
    "active_pointer_file_sha256": (
        "9c3d28fb770b3c8b53acee419abdefe1fed21fb14d2854c9f2f5fd685566d0fc"
    ),
}
NVIDIA_V5_ATTEMPT8_RESUME_AUTHORITY_TEXT = (
    "phase5-nvidia-v5-three-validated-post-attempt7-resume-v1:provider=nvidia-nim:model=minimaxai/min"
    "imax-m3:endpoint=https://integrate.api.nvidia.com/v1/chat/completions:prompt-contract-commit=002"
    "60595c7ed90cf34a6fbef219c40155fe23abe:predecessor-implementation-commit=25e374c758294bc333438162"
    "382223f44b7b2b5d:attempt3-6-implementation-commit=2626fe6bf484f2bfbf21950be14ec42b1c97ef1b:immed"
    "iate-predecessor-resume-authority=bbcd6a7d8c1b795ad302ce017f4831612d95602d8b75e11a4b247f5bdcfc57"
    "1e:immediate-predecessor-offline-preflight-receipt=9e1a9ee055e190849f97285150e17d120094a450331f1"
    "24fffd0c69d7fbbd46b:immediate-predecessor-live-authority-receipt=eb59dcbb63c8efcf873ef02016cc70a"
    "8f8233f1d6da9c854441e537d50703d10:immediate-predecessor-root-manifest=99c66d743b6f2b1f5c63440a6c"
    "828d1665d1f532945cbcf918ecdd6c05ac6028:immediate-predecessor-authority-file=eb59dcbb63c8efcf873e"
    "f02016cc70a8f8233f1d6da9c854441e537d50703d10:immediate-predecessor-live-start-self=445ac1ca687ff"
    "a870b7f0eddf8b3a8dfd5a7766a09b32648bcb8ca7bb7096ae3:immediate-predecessor-live-start-file=6cfca2"
    "7b781756da70fb70f7096810ea77a4ba62beab6a68f4615eb4ecd432ba:immediate-predecessor-consumption-pol"
    "icy=consumed-terminal-never-restart-never-reinvoke:prompt-version=phase5-demo-profile-sentinel-j"
    "son.v5:prompt-sha256=aaa0328deaae58999b96eb9a43f176e589eb95319c3a80e9cd2978b23b925b3a:request-co"
    "ntract=EXACT_COMPLETE_EXAMPLE_V1:source-inventory=2245b16896f273b926bae4ee60efe09c3472271642c42b"
    "8ec0a6fcc40f99df1e:all-dev-v5-request-manifest=fe0179b3f316ca5b6f5805052559a17756cac555bbd273d98"
    "b1324e9e9c3225e:all-dev-schema-example-manifest=d9d716942af28a5ac2bacc647112576b03f32f0a07c132b0"
    "7b752ec95a687852:remaining-v5-request-manifest=6be9d7ab3d54430bb88e53e5b21e54d80f6db0798078dad90"
    "875a36b3411bf8f:remaining-schema-example-manifest=958cf03e919bc76654a256c2e56a05770ac986f3dac4e9"
    "d37f1304a2c4252c92:predecessor-resume-authority=2d6067aa3eb3c03ad419ab915e16ebda43a9524d5ed2eeb7"
    "67556259efccd170:predecessor-authority-receipt=12c350a257ab6326949f35938dbed9d104557cb812bf70094"
    "7891e3f1823f6a9:predecessor-root-manifest=a89142fa7ec21e5f862d361c0ac82a0df0cc31e1b8f4f99aff4696"
    "87258804e0:predecessor-authority-file=0def638830d74575a488388d699a774f9d6af3295a8fa30491421ff29c"
    "3e6b62:attempt1-place=place:01ffd19d7d710b9197a37689a65f8d10214be68ff31cf947ebf5b3251a274015:att"
    "empt1-lineage-authority=eb8ae4a76babea5012eeccc49e6484deabda17c373ddb3d55167f3bdda1277f2:attempt"
    "1-root-manifest=2c3b2dd4d1be3159a3600cb71789206ff1b452983484d80c3b717ed09d757b64:attempt1-attemp"
    "t-self=31951a8d0928261b3e5d88bcd8629613e662c3160af7c44d9d5c712dbfbde12b:attempt1-attempt-file=e4"
    "b49689c1cc1fcfe20f721e1aa8e8f0461f6fb951c437c7c0d6c438f9a39dcd:attempt1-journal=efcce9b437b6b4c5"
    "da5ba5ac90849e7e76849392d7539e2bedad878515eb5d39:attempt1-contract-request=5caa5678525ae5c69a865"
    "cb89ad71d90a29b6f33bf0ddafddac49fe0a0f2aadc:attempt1-http-request=e705cd32db494530b4f66c0c1033f1"
    "9a518fca99b2c49cb3e51533e76b305dfd:attempt1-response=a36c4649f1cae74f95f72d67baf76497313145907b0"
    "bed3e903b15c7a4744798:attempt1-outcome=RESPONSE_INVALID:attempt1-http-status=200:attempt1-termin"
    "al-self=e26194dbe3d70468dcdeb8580e2510a720b070299bc42865206d18766057e2e2:attempt1-terminal-file="
    "3aa5ba7c0b2b8ef937d3c9c935c1aff2017394e6ef8135357dbe27b9b1b0667b:attempt1-failure-self=e2430c7fe"
    "0180aea83382f5caabe1c1ab09b4df7911870a049888eaf136785e5:attempt1-failure-manifest=4c6250ddac5b4a"
    "7394ff49f95a0258632dc0cc6e86995adb232a346c2585a1b0:attempt1-failure-file=3fa1892153adfe78ee67281"
    "aeb240b0e34d6227be9f16d0b291fecb9c31ea776:attempt2-place=place:01ffd19d7d710b9197a37689a65f8d102"
    "14be68ff31cf947ebf5b3251a274015:attempt2-lineage-authority=d35af02c8865a2f03561bd52024c6934bf393"
    "73298ea9def54d3c55c2f1cce7e:attempt2-root-manifest=be6c2bec5db91e08d54cc20974e1e604363b116c35f9e"
    "5d60da7af61a5801b17:attempt2-attempt-self=60266facd4cd0cacebd7b9ec161c5990e05185af7cd77e2578ed03"
    "00827a3a9d:attempt2-attempt-file=8521928e5147fb66ac62769b311e0dd3115343f8acd8bd2faf1330ccaa4b8ac"
    "9:attempt2-journal=333c1d8aa5d81e0fae7c7a11c22508434b8f0546fb0f0044e39f8e0989576cc3:attempt2-con"
    "tract-request=5caa5678525ae5c69a865cb89ad71d90a29b6f33bf0ddafddac49fe0a0f2aadc:attempt2-http-req"
    "uest=e705cd32db494530b4f66c0c1033f19a518fca99b2c49cb3e51533e76b305dfd:attempt2-response=0672a656"
    "dccbd0dffc75a1e32a28f7126d5b351d6285c815656ab1f2a44956fc:attempt2-outcome=RESPONSE_INVALID:attem"
    "pt2-http-status=200:attempt2-terminal-self=145cfbe7e68745ab642607d934e57d90da22c107eef9eb352b701"
    "40a275bea17:attempt2-terminal-file=4a5f39fee7e85366e42e8ab489a7e83896ce415239c6104fbb0ad5309ba7e"
    "241:attempt2-failure-self=555d8aaccbaa0dcb49e506cf7f20d5d8608999cde2e37ae4fe118dc3db312e66:attem"
    "pt2-failure-manifest=061e9b0527c0bba9a7c5261c42e508ca5bc8f6e1ed7cd9300c2a13501ea8b68f:attempt2-f"
    "ailure-file=5e3c9acad3fbe29600546541b510706b0cee2980c2c9a4f40e948f728fd8e2a7:attempt3-place=plac"
    "e:01ffd19d7d710b9197a37689a65f8d10214be68ff31cf947ebf5b3251a274015:attempt3-lineage-authority=2d"
    "6067aa3eb3c03ad419ab915e16ebda43a9524d5ed2eeb767556259efccd170:attempt3-reservation-self=355ce5f"
    "88be38a1aa382ee5d8b6414401214de35ca436df858756d77e13f1706:attempt3-reservation-file=acbf4e8c2bd2"
    "062b0a3277accd07bcc00df4edefa2d8f4ff0f257c0ceb4d6db1:attempt3-attempt-self=2871b6d1967c8b910855a"
    "1d583adf4d915aa518a4d6b2a3382a282bce7aedc63:attempt3-attempt-file=52876de2e5b492c8e62fc47a0cef37"
    "b07d2b1ffea45c434a524c0fd6d5779a95:attempt3-journal=e5fa4eec68f14b8fe303975f35f7a3a3f324842af6ef"
    "aeffe0cf8aba80376894:attempt3-contract-request=3f8ba29065922d51bb7592bc0e7402f2c4370a0784b816482"
    "232cc13bf81bb49:attempt3-http-request=d5046ee8f0433cd7d63be7c0b6030c79e73e27aba8e9147075b49495ef"
    "8b4e83:attempt3-response=4c662d2992cfef894291152d819212057b1ceba5ec175699f181f4ebe2a4f154:attemp"
    "t3-outcome=VALIDATED:attempt3-http-status=200:attempt3-error-code=none:attempt3-retry=false:atte"
    "mpt3-profile=ceea4848bc038b33ae4fa3fea46a6d5b28ce18f9a70d18faaa5689c6f33cb9f6:attempt4-place=pla"
    "ce:028ea3b319c4d0a45d0031d3f2aa78dfe0b40d272eb637fceaecdba10aff1a4a:attempt4-lineage-authority=2"
    "d6067aa3eb3c03ad419ab915e16ebda43a9524d5ed2eeb767556259efccd170:attempt4-reservation-self=ff1a3f"
    "c5e8da0d6c2f8a967b491c9f643655cf08bff3c8ceab50179373aff6f1:attempt4-reservation-file=a466b18e4f4"
    "eff5956dd1f2e2805ed7c93f09bbf319218328da8cab5299ca8e9:attempt4-attempt-self=3cdd40d2c9615d8d833f"
    "2c17e70772d78d0493eed4a20774d2d45b8645a529c7:attempt4-attempt-file=dc8140364c626431bb15df96a7339"
    "d8af207254cc92a2ac9f72bd79b34a40274:attempt4-journal=99fc39656eea72869939e8c5a1c691906c468788f8c"
    "d8e661272bf7604d1f5c4:attempt4-contract-request=4c081bb9bc9145242dd8796aace7fa4822b6a488ce44e516"
    "131ffdb423d1bcaf:attempt4-http-request=c413f52cfe2800e66800f7e06e0a7028208ad13c07ec91daf80e3a6b8"
    "6ca748f:attempt4-response=17be0c4a166b295b18dd81be37a529e9b8bc8d6303bda62f44d8f16de3c94311:attem"
    "pt4-outcome=VALIDATED:attempt4-http-status=200:attempt4-error-code=none:attempt4-retry=false:att"
    "empt4-profile=1b42e24e559cf3b4164c0ae7929405b150af8341764d0b159262ae88ee184076:attempt5-place=pl"
    "ace:119da6ea8756c8731f65f3fae9c5553ac16c8317f6688a68013cf3ead04916d8:attempt5-lineage-authority="
    "2d6067aa3eb3c03ad419ab915e16ebda43a9524d5ed2eeb767556259efccd170:attempt5-reservation-self=db22f"
    "2320ee5d3d31bbccd8c46db9518fe24dc51483a4ee7bfd62e74de68d758:attempt5-reservation-file=c283ff8b4f"
    "3f9927f6d86d18a95f31bb0bfc1cb90ed70f3d0b4a5c2d57bb3363:attempt5-attempt-self=7196ea968459e5adda5"
    "b5189708728ac96b4f870cd852508ef46b949eea8ea8b:attempt5-attempt-file=9b1aedd28121de79413c6cd8a442"
    "7ede9f796e6ec4987b250974a20737348b5f:attempt5-journal=0e38976ca16954f45e4b2d682a9d25b3ebd0402121"
    "0e1824f181ef9d69222d83:attempt5-contract-request=945fbfb904560eef36befe54574c0cccba101c335f22524"
    "fae3461a560487d23:attempt5-http-request=727c024e0df6ee0714e28783facacb552d88e6af80955b24a829427a"
    "6dfdfde2:attempt5-response=6922b37d5f73590e437df5a9b802584b736382c72f9f6183736ec2cd64fad29f:atte"
    "mpt5-outcome=VALIDATED:attempt5-http-status=200:attempt5-error-code=none:attempt5-retry=false:at"
    "tempt5-profile=4feff1d3e1c1bc727c6511d879706b0fbace2527c731d5e6df5580590f5596ae:attempt6-place=p"
    "lace:1382768797abf757779da08f8ad806b8403ffb3f400dab9c91446e368c024f4b:attempt6-lineage-authority"
    "=2d6067aa3eb3c03ad419ab915e16ebda43a9524d5ed2eeb767556259efccd170:attempt6-reservation-self=5c46"
    "6ac0e82f2542c6a1ff928db76d5658c882d93d14257f70945b5d3a92b248:attempt6-reservation-file=f8355b90d"
    "433a1c78bbd4ff8abff0bea8cc0050fd1178dfb08198bf5c1113e83:attempt6-attempt-self=b978308d8605d581f8"
    "3861644b63cd8b16d148b4c42a4b897f959dc61be51be8:attempt6-attempt-file=9e964ccb6889de55a8de5c9c237"
    "88ff60423d9fd5b06adbbaad7163ee5b3a716:attempt6-journal=82895bce0e2829db9fa71f1ba56540e24e0b31ade"
    "2ba49a86cd925e8f53b76a5:attempt6-contract-request=48a706dcddfd974953fc6d64dfed8acb202a2aac2498c4"
    "46d45df127f00d3bc3:attempt6-http-request=ac8302059f9cdf24a956a1077b4eec20c74d37670b183a491100ca4"
    "828a90cb5:attempt6-response=d805415abe66787220a2eabaaf865f8750d0235358485a790b51d7edffb8b876:att"
    "empt6-outcome=RESPONSE_INVALID:attempt6-http-status=200:attempt6-error-code=PROVIDER_RESPONSE_TE"
    "RMINAL_INVALID:attempt6-retry=false:attempt6-terminal-self=5c14a3e2f9679f9ad8de0af4c579835dfa2ae"
    "8265b2d3f88fedcbb2b0fc7cbb7:attempt6-terminal-file=dfe448ebf5ab3614f6cb25631f07620c68e951ecdd9db"
    "87b6d833fc0cb6d4862:attempt6-failure-self=a11f3dad30d6fac9be72a3f1efe9073a204b2bc55eaee3f6551afc"
    "37c4d95f41:attempt6-failure-file=757655484d36e64cadf0a48f2da4cebd2cec7bc350632b5bd0e01ec7e939d84"
    "9:attempt6-failure-manifest=7b2ca9d2f318352f6e8e7340962783122c759e5895c04248546eeea6f8de7cd3:att"
    "empt6-failure-attempts-file=61c852d06259ca30f7b47fc82e3974dfa9b6ced1e1002e6f559336fd611815dd:att"
    "empt6-response-disposition=immutable-invalid-no-profile-no-raw-replay:attempt6-publishable=false"
    ":attempt7-place=place:1382768797abf757779da08f8ad806b8403ffb3f400dab9c91446e368c024f4b:attempt7-"
    "lineage-authority=bbcd6a7d8c1b795ad302ce017f4831612d95602d8b75e11a4b247f5bdcfc571e:attempt7-auth"
    "ority-receipt=eb59dcbb63c8efcf873ef02016cc70a8f8233f1d6da9c854441e537d50703d10:attempt7-namespac"
    "e-manifest=99c66d743b6f2b1f5c63440a6c828d1665d1f532945cbcf918ecdd6c05ac6028:attempt7-live-start-"
    "self=445ac1ca687ffa870b7f0eddf8b3a8dfd5a7766a09b32648bcb8ca7bb7096ae3:attempt7-live-start-file=6"
    "cfca27b781756da70fb70f7096810ea77a4ba62beab6a68f4615eb4ecd432ba:attempt7-reservation-self=f97341"
    "01f7386e57416ecf0a91b4b364d804df9f554628829f9f193aa3010592:attempt7-reservation-file=fa9bd72ff95"
    "e5f62c74192c26f148c057ea79179395382711aec72d9bdce2486:attempt7-attempt-self=b7f330f21b83e7aa1056"
    "fb2d9b0e7f4205b285c84cc0827b20bcba110f49f438:attempt7-attempt-file=1ac72aa23164f891cb756c7d45a66"
    "00249be008a91191a72792a74d49a81a969:attempt7-journal=ac362ae561dc186cbe22a7f493cfb8eb8c8eef6587c"
    "aa5c8d871c597b6198787:attempt7-contract-request=28f67f56eaa5cdc5d8b3ee8563cd2057be12de203bf8b9aa"
    "9fd40ec9e350c623:attempt7-http-request=ac8302059f9cdf24a956a1077b4eec20c74d37670b183a491100ca482"
    "8a90cb5:attempt7-response=5fbb46d717e8f567a5d4a68557458ce6d70d7dabbeb94f9eefe574cc41d6a6f9:attem"
    "pt7-outcome=RESPONSE_INVALID:attempt7-http-status=200:attempt7-error-code=PROVIDER_RESPONSE_TERM"
    "INAL_INVALID:attempt7-retry=false:attempt7-terminal-self=f57707108ca573f1a0d5e7cb458a14a4417fbed"
    "1e16e43b5d3e348aa39a87394:attempt7-terminal-file=cf3bd45ac382e5edd4dbea8f2af5ab457125c0ee831c275"
    "af49a30d4ccb15fc8:attempt7-failure-self=25265f60bddc0fa4224b68341b3e2e38861ab84bdfdf912dd4653648"
    "190cdf17:attempt7-failure-file=473855f1e0268cd984856c1fc8b01b7954ad9e091210663a158f98403f5b9c27:"
    "attempt7-failure-manifest=f6b38bdab9ce97315ca25f066ac7934691e38cb312636e015c31a36ea3cbcd2f:attem"
    "pt7-failure-attempts-file=da1bf88c8df1405e52ada6d00e369cca8f4dc626ea9ac0372f3c9f43fc85bb3a:attem"
    "pt7-response-disposition=immutable-invalid-no-profile-no-raw-replay:attempt7-publishable=false:p"
    "redecessor-consumed-attempt-manifest=c6eb72df0c85764ca0674868e41e09dbeacf08ff5c773c6b43b642d636e"
    "87e8e:consumed-attempt-manifest=da1bf88c8df1405e52ada6d00e369cca8f4dc626ea9ac0372f3c9f43fc85bb3a"
    ":consumed-attempt-manifest-canonicalization=canonical-json-full-attempts-1-7-v1:consumed-http-at"
    "tempts=7:validated-attempts=3,4,5:validated=3:validated-place-ids=place:01ffd19d7d710b9197a37689"
    "a65f8d10214be68ff31cf947ebf5b3251a274015,place:028ea3b319c4d0a45d0031d3f2aa78dfe0b40d272eb637fce"
    "aecdba10aff1a4a,place:119da6ea8756c8731f65f3fae9c5553ac16c8317f6688a68013cf3ead04916d8:validated"
    "-membership=150845a40818d1138478489988bd2f16a74c2b6a7938d733c5ab7fc27d8c04d3:validated-profile-s"
    "ha256=ceea4848bc038b33ae4fa3fea46a6d5b28ce18f9a70d18faaa5689c6f33cb9f6,1b42e24e559cf3b4164c0ae79"
    "29405b150af8341764d0b159262ae88ee184076,4feff1d3e1c1bc727c6511d879706b0fbace2527c731d5e6df558059"
    "0f5596ae:validated-profile-manifest=abcff5db145431d6bdce9ce8f1ca60cf124caa914e7498313c7465f79c06"
    "0823:profile-replay-created-at-policy=attempt-started-at-utc:remaining=21:remaining-place-ids=pl"
    "ace:1382768797abf757779da08f8ad806b8403ffb3f400dab9c91446e368c024f4b,place:13e97270ee89f51469e43"
    "51a78e78667cb280a79bfff31b09e79dbcf5657cb3d,place:2d9350874386a80df162df9a81d99c27dd3daee94eafb8"
    "685c410ac37bd33f22,place:2e45cd43f9ada5f923bf702baa120595da9b1a4a1205f217e05e00dfc403dc18,place:"
    "2ee63c737daf239718e16ee2a53222db886be3f7d9c345a2ed4e7c8ad02536a0,place:33515ac990a21f3fd8980f963"
    "625adcf6bc95eedf826625c7124d9c44eaade19,place:342fbc04c8c21313b3229ab32d84bdd111efb76bd029c00c96"
    "2a836d9807339f,place:4028f3f38d5ccdd7f97a4c80a21f3416a40fd387d7e4d630b2884c640f01ccc3,place:4b57"
    "cdef6b3930b551b3e51f98bd4e6f79be8c79ea2d0b74a2b5b57c65c690c0,place:50723a8c5ce99fa340e205db0cabd"
    "5a68e649a2e461ee4fd3b6ff8b7f7ca3f59,place:51e051dfa095668ec9f761e4dbf9ecb06f47eb9994e1b2aa245181"
    "2fb4c43a1f,place:55f2606ec1c3c53f6742537bc95bb1a3c7951ca92254eaf0aa9a164033908326,place:575b3561"
    "85f8edd4b35d564c990d9dc04392c80e3bebf8dd967c77fe7f15b1b2,place:86781b603cb2264558c59743bc4422e63"
    "c6224cb971e467ebeed72f304e423de,place:88364b595917974034901067047d4b3c6c4bf54f0aaa9390284a587fdf"
    "690528,place:aa92b36a3a70b499f58c65ed2f3c26908a23c631824bd811ecb6f523ebdc0c44,place:cc228be94470"
    "e9b7330d88b4e756db170fec5e90e3364e77ff86826a32455ccd,place:ce7793c3d7c6e0abac98a091248e2609ea3e3"
    "275e92c874e916abd437156726a,place:cf5037785cc1b065f66890410c07ed0013f9148c302faef609b91922161fbb"
    "a4,place:d18e2ecf50dfb21415191c28a18badafc767ff17d8feddc91b7e0b54f506d40d,place:f662d1bd7b4626d1"
    "b80f64cf0409a4674b1363f783a0d79ed2e8f23327584323:remaining-membership=4376b46dfb100f38a643022d81"
    "9c4e061b5da4be6ee2c3f3cb705036d559d150:membership-canonicalization=ordered-dev24-minus-validated"
    "-v1:attempts-start=8:cumulative-http-cap=30:cumulative-http-remaining=23:new-http-cap=23:future-"
    "place-request-count=21:concurrency=1:min-interval-seconds=60:whole-attempt-timeout-seconds=300:t"
    "emperature=0:top-p=omitted-provider-default-0.95:max-tokens=8192:seed=0:thinking-mode=disabled:o"
    "utput-contract=exact-sentinel-bounded-json-object-with-complete-example:response-format=omitted-"
    "undocumented-for-exact-model:tools=omitted:json-start=<<<ITDA_PROFILE_JSON_V3_START_4F3A6C91>>>:"
    "json-end=<<<ITDA_PROFILE_JSON_V3_END_9B7D2E65>>>:max-json-bytes=65536:first-429=circuit-break-ba"
    "tch-no-retry:terminal-invalid=circuit-break-batch-no-retry:invalid-attempts=1,2,6,7-no-replay:va"
    "lidated-attempts-policy=3,4,5-local-replay-only-no-http:profile-lineage=v5-required-no-v4-masque"
    "rade:blind=forbidden:generation=forbidden-until-exact-24-current-valid-v5:activation=forbidden-u"
    "ntil-exact-24:single-future-live-invocation=true:grammar-implementation=forbidden-until-explicit"
    "-execution-approval:provider-network=forbidden-until-exact-authority-and-separate-execution-appr"
    "oval:derivation-only-until-explicit-execution-approval=true:requires-explicit-future-authority=t"
    "rue:historical-generation=4354deace22c92a821f7ada3ff307dff775736fa7a9618a2eab3b2a29bc96581:histo"
    "rical-release=59c3a6379e1e3de6ef67d95947d80f39d97c21bdcbf368d0080e5d8aa7224c50:active-pointer-fi"
    "le=9c3d28fb770b3c8b53acee419abdefe1fed21fb14d2854c9f2f5fd685566d0fc"
)
NVIDIA_V5_ATTEMPT8_RESUME_AUTHORITY_SHA256 = hashlib.sha256(
    NVIDIA_V5_ATTEMPT8_RESUME_AUTHORITY_TEXT.encode("utf-8")
).hexdigest()
NVIDIA_V5_ATTEMPT8_RESUME_BINDINGS: Mapping[str, object] = {
    **NVIDIA_V5_THREE_VALIDATED_RESUME_BINDINGS,
    "predecessor_authority_sha256": NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_SHA256,
    "predecessor_authority_receipt_sha256": (
        "9e1a9ee055e190849f97285150e17d120094a450331f124fffd0c69d7fbbd46b"
    ),
    "predecessor_live_authority_receipt_sha256": (
        "eb59dcbb63c8efcf873ef02016cc70a8f8233f1d6da9c854441e537d50703d10"
    ),
    "predecessor_root_manifest_sha256": (
        "99c66d743b6f2b1f5c63440a6c828d1665d1f532945cbcf918ecdd6c05ac6028"
    ),
    "predecessor_authority_file_sha256": (
        "eb59dcbb63c8efcf873ef02016cc70a8f8233f1d6da9c854441e537d50703d10"
    ),
    "predecessor_live_start_sha256": (
        "445ac1ca687ffa870b7f0eddf8b3a8dfd5a7766a09b32648bcb8ca7bb7096ae3"
    ),
    "predecessor_live_start_file_sha256": (
        "6cfca27b781756da70fb70f7096810ea77a4ba62beab6a68f4615eb4ecd432ba"
    ),
    "failure_sha256": "25265f60bddc0fa4224b68341b3e2e38861ab84bdfdf912dd4653648190cdf17",
    "failure_file_sha256": ("473855f1e0268cd984856c1fc8b01b7954ad9e091210663a158f98403f5b9c27"),
    "failure_manifest_sha256": ("f6b38bdab9ce97315ca25f066ac7934691e38cb312636e015c31a36ea3cbcd2f"),
    "failure_attempts_file_sha256": (
        "da1bf88c8df1405e52ada6d00e369cca8f4dc626ea9ac0372f3c9f43fc85bb3a"
    ),
    "terminal_sha256": "f57707108ca573f1a0d5e7cb458a14a4417fbed1e16e43b5d3e348aa39a87394",
    "terminal_file_sha256": ("cf3bd45ac382e5edd4dbea8f2af5ab457125c0ee831c275af49a30d4ccb15fc8"),
    "attempt7_place_id": ("place:1382768797abf757779da08f8ad806b8403ffb3f400dab9c91446e368c024f4b"),
    "attempt7_reservation_sha256": (
        "f9734101f7386e57416ecf0a91b4b364d804df9f554628829f9f193aa3010592"
    ),
    "attempt7_reservation_file_sha256": (
        "fa9bd72ff95e5f62c74192c26f148c057ea79179395382711aec72d9bdce2486"
    ),
    "attempt7_attempt_sha256": ("b7f330f21b83e7aa1056fb2d9b0e7f4205b285c84cc0827b20bcba110f49f438"),
    "attempt7_attempt_file_sha256": (
        "1ac72aa23164f891cb756c7d45a6600249be008a91191a72792a74d49a81a969"
    ),
    "attempt7_journal_sha256": ("ac362ae561dc186cbe22a7f493cfb8eb8c8eef6587caa5c8d871c597b6198787"),
    "attempt7_contract_request_sha256": (
        "28f67f56eaa5cdc5d8b3ee8563cd2057be12de203bf8b9aa9fd40ec9e350c623"
    ),
    "attempt7_http_request_sha256": (
        "ac8302059f9cdf24a956a1077b4eec20c74d37670b183a491100ca4828a90cb5"
    ),
    "attempt7_response_sha256": (
        "5fbb46d717e8f567a5d4a68557458ce6d70d7dabbeb94f9eefe574cc41d6a6f9"
    ),
    "validated_attempt_numbers": (3, 4, 5),
    "terminal_invalid_attempt_numbers": (1, 2, 6, 7),
}

CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256 = (
    "b295415aa55a43aae689c1d558b8c72f4e211ebe749612a036496165f34f0e25"
)
CODING_PLAN_MODEL_WEIGHT = 1
CODING_PLAN_AUTHORITY_TEXT = (
    "use-phase5-coding-plan:base=https://api.z.ai/api/coding/paas/v4:"
    "model=glm-5v-turbo:plan-weight=1:new-http-attempts=30:"
    "evidence-sha256=" + CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256
)
CODING_PLAN_AUTHORITY_SHA256 = hashlib.sha256(
    CODING_PLAN_AUTHORITY_TEXT.encode("utf-8")
).hexdigest()
PRICING_VERSION = "zai-glm-5v-turbo-2026-08-10"
PRICING_SOURCE_URL = "https://docs.z.ai/guides/overview/pricing"
MAX_CONTEXT_INPUT_TOKENS = 200_000
MAX_OUTPUT_TOKENS = 2048
ATTEMPT_RESERVATION_MICRO_USD = 248_192
MAX_RUN_COST_MICRO_USD = 5_000_000
RERUN_COST_CAP_MICRO_USD = 7_500_000
CUMULATIVE_RERUN_CAP_MICRO_USD = 12_500_000
PRIOR_COMMITTED_LOWER_MICRO_USD = 4_751_809
PRIOR_COMMITTED_UPPER_MICRO_USD = 5_000_000
RERUN_AUTHORITY_TEXT = (
    "approve-phase5-zai-rerun:cumulative-reservation-cap=12500000-micro-usd:"
    "new-http-attempts=30:model=glm-5v-turbo"
)
RERUN_AUTHORITY_SHA256 = hashlib.sha256(RERUN_AUTHORITY_TEXT.encode("utf-8")).hexdigest()
MAX_HTTP_ATTEMPTS = 30
MAX_PROVIDER_RESPONSE_BYTES = 4 * 1024 * 1024

AxisId = Literal["H", "E", "R"]
SourceKind = Literal["TOUR_API_DESCRIPTION", "ODII_TRANSCRIPT"]

_AXIS_ORDER = ("H", "E", "R")
_SUBATTRIBUTE_ORDER = tuple(
    (
        *tuple(f"H{index}" for index in range(1, 5)),
        *tuple(f"I{index}" for index in range(1, 5)),
        *tuple(f"R{index}" for index in range(1, 5)),
    )
)
_MISMATCH_ORDER = tuple(f"M{index}" for index in range(1, 7))
_FORBIDDEN_KEYS = frozenset(
    {
        "api_key",
        "authorization",
        "bearer_token",
        "blind",
        "blind_ids",
        "blind_membership",
        "blind_payload",
        "credential",
        "credentials",
        "expert_label",
        "expert_labels",
        "label",
        "labels",
        "raw_image",
        "raw_response",
        "raw_response_body",
        "release_authority",
    }
)


def _reject_forbidden_keys(value: object) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if isinstance(key, str) and key.casefold() in _FORBIDDEN_KEYS:
                raise ValueError(f"forbidden profile materialization field: {key.casefold()}")
            _reject_forbidden_keys(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            _reject_forbidden_keys(nested)


def seal_demo_contract(payload: Mapping[str, object], *, digest_field: str) -> dict[str, object]:
    sealed = dict(payload)
    sealed.pop(digest_field, None)
    sealed[digest_field] = canonical_sha256(sealed)
    return sealed


def _require_self_digest(model: StrictContract, *, digest_field: str) -> None:
    payload = model.model_dump(mode="json", exclude={digest_field})
    if getattr(model, digest_field) != canonical_sha256(payload):
        raise ValueError(f"{digest_field} does not match canonical content")


def _ceil_div(numerator: int, denominator: int) -> int:
    return (numerator + denominator - 1) // denominator


class ProviderTokenUsage(StrictContract):
    prompt_tokens: Annotated[int, Field(strict=True, ge=0, le=MAX_CONTEXT_INPUT_TOKENS)]
    completion_tokens: Annotated[int, Field(strict=True, ge=0, le=MAX_OUTPUT_TOKENS)]
    cached_tokens: Annotated[int, Field(strict=True, ge=0, le=MAX_CONTEXT_INPUT_TOKENS)]

    @model_validator(mode="after")
    def validate_cached_subset(self) -> Self:
        if self.cached_tokens > self.prompt_tokens:
            raise ValueError("cached tokens cannot exceed prompt tokens")
        return self


class NvidiaProviderTokenUsage(StrictContract):
    """OpenAI-compatible NVIDIA usage with an explicit zero cache default."""

    prompt_tokens: Annotated[int, Field(strict=True, ge=0, le=MAX_CONTEXT_INPUT_TOKENS)]
    completion_tokens: Annotated[int, Field(strict=True, ge=0, le=8192)]
    cached_tokens: Annotated[int, Field(strict=True, ge=0, le=MAX_CONTEXT_INPUT_TOKENS)] = 0
    total_tokens: Annotated[int, Field(strict=True, ge=0, le=MAX_CONTEXT_INPUT_TOKENS + 8192)]

    @model_validator(mode="after")
    def validate_totals(self) -> Self:
        if self.cached_tokens > self.prompt_tokens:
            raise ValueError("cached tokens cannot exceed prompt tokens")
        if self.total_tokens != self.prompt_tokens + self.completion_tokens:
            raise ValueError("NVIDIA total token count is inconsistent")
        return self


class ProviderUsageCharge(StrictContract):
    uncached_input_tokens: Annotated[int, Field(strict=True, ge=0)]
    cached_input_tokens: Annotated[int, Field(strict=True, ge=0)]
    output_tokens: Annotated[int, Field(strict=True, ge=0)]
    uncached_input_micro_usd: Annotated[int, Field(strict=True, ge=0)]
    cached_input_micro_usd: Annotated[int, Field(strict=True, ge=0)]
    output_micro_usd: Annotated[int, Field(strict=True, ge=0)]
    total_micro_usd: Annotated[int, Field(strict=True, ge=0, le=ATTEMPT_RESERVATION_MICRO_USD)]


_PRICING_SAFE_FACTS = {
    "version": PRICING_VERSION,
    "source_url": PRICING_SOURCE_URL,
    "currency": "USD",
    "billing_unit_tokens": 1_000_000,
    "uncached_input_rate_numerator": 1_200_000,
    "cached_input_rate_numerator": 240_000,
    "output_rate_numerator": 4_000_000,
    "cached_input_storage_label": "Limited-time Free",
    "worst_case_input_tokens": MAX_CONTEXT_INPUT_TOKENS,
    "max_output_tokens": MAX_OUTPUT_TOKENS,
    "attempt_reservation_micro_usd": ATTEMPT_RESERVATION_MICRO_USD,
}
PRICING_SNAPSHOT_SHA256 = canonical_sha256(_PRICING_SAFE_FACTS)


class PricingSnapshot(StrictContract):
    version: Literal["zai-glm-5v-turbo-2026-08-10"] = "zai-glm-5v-turbo-2026-08-10"
    source_url: Literal["https://docs.z.ai/guides/overview/pricing"] = (
        "https://docs.z.ai/guides/overview/pricing"
    )
    currency: Literal["USD"] = "USD"
    billing_unit_tokens: Literal[1_000_000] = 1_000_000
    uncached_input_rate_numerator: Literal[1_200_000] = 1_200_000
    cached_input_rate_numerator: Literal[240_000] = 240_000
    output_rate_numerator: Literal[4_000_000] = 4_000_000
    cached_input_storage_label: Literal["Limited-time Free"] = "Limited-time Free"
    worst_case_input_tokens: Literal[200_000] = 200_000
    max_output_tokens: Literal[2048] = 2048
    attempt_reservation_micro_usd: Literal[248_192] = 248_192
    pricing_snapshot_sha256: Sha256 = PRICING_SNAPSHOT_SHA256

    @model_validator(mode="after")
    def validate_snapshot_digest(self) -> Self:
        if self.pricing_snapshot_sha256 != PRICING_SNAPSHOT_SHA256:
            raise ValueError("pricing snapshot digest drifted")
        return self

    def charge(self, usage: ProviderTokenUsage) -> ProviderUsageCharge:
        uncached = usage.prompt_tokens - usage.cached_tokens
        uncached_cost = _ceil_div(
            uncached * self.uncached_input_rate_numerator,
            self.billing_unit_tokens,
        )
        cached_cost = _ceil_div(
            usage.cached_tokens * self.cached_input_rate_numerator,
            self.billing_unit_tokens,
        )
        output_cost = _ceil_div(
            usage.completion_tokens * self.output_rate_numerator,
            self.billing_unit_tokens,
        )
        return ProviderUsageCharge(
            uncached_input_tokens=uncached,
            cached_input_tokens=usage.cached_tokens,
            output_tokens=usage.completion_tokens,
            uncached_input_micro_usd=uncached_cost,
            cached_input_micro_usd=cached_cost,
            output_micro_usd=output_cost,
            total_micro_usd=uncached_cost + cached_cost + output_cost,
        )


class DemoProfileMaterializationConfig(StrictContract):
    schema_version: Literal["itda.demo-profile-materialization-config.v1"] = (
        "itda.demo-profile-materialization-config.v1"
    )
    endpoint: Literal["https://api.z.ai/api/paas/v4/chat/completions"] = (
        "https://api.z.ai/api/paas/v4/chat/completions"
    )
    model: Literal["glm-5v-turbo"] = "glm-5v-turbo"
    authorization_scheme: Literal["Bearer"] = "Bearer"
    max_tokens: Literal[2048] = 2048
    connect_seconds: Literal[10] = 10
    pool_seconds: Literal[10] = 10
    write_seconds: Literal[30] = 30
    read_seconds: Literal[180] = 180
    attempt_deadline_seconds: Literal[300] = 300
    concurrency: Literal[1] = 1
    follow_redirects: Literal[False] = False
    trust_env: Literal[False] = False
    max_http_attempts: Literal[30] = 30
    max_run_cost_micro_usd: Literal[5_000_000] = 5_000_000
    attempt_reservation_micro_usd: Literal[248_192] = 248_192
    pricing: PricingSnapshot = Field(default_factory=PricingSnapshot)


class CodingPlanProfileMaterializationConfig(StrictContract):
    schema_version: Literal["itda.coding-plan-profile-materialization-config.v1"] = (
        "itda.coding-plan-profile-materialization-config.v1"
    )
    base_url: Literal["https://api.z.ai/api/coding/paas/v4"] = "https://api.z.ai/api/coding/paas/v4"
    endpoint: Literal["https://api.z.ai/api/coding/paas/v4/chat/completions"] = (
        "https://api.z.ai/api/coding/paas/v4/chat/completions"
    )
    model: Literal["glm-5v-turbo"] = "glm-5v-turbo"
    provider_lane: Literal["CODING_PLAN_SUBSCRIPTION"] = "CODING_PLAN_SUBSCRIPTION"
    accounting_mode: Literal["CODING_PLAN_WEIGHT"] = "CODING_PLAN_WEIGHT"
    entitlement_evidence_sha256: Sha256 = CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256
    model_weight: Literal[1] = 1
    authorization_scheme: Literal["Bearer"] = "Bearer"
    max_tokens: Literal[2048] = 2048
    connect_seconds: Literal[10] = 10
    pool_seconds: Literal[10] = 10
    write_seconds: Literal[30] = 30
    read_seconds: Literal[180] = 180
    attempt_deadline_seconds: Literal[300] = 300
    concurrency: Literal[1] = 1
    follow_redirects: Literal[False] = False
    trust_env: Literal[False] = False
    max_http_attempts: Literal[30] = 30

    @classmethod
    def for_authorized_base(
        cls,
        *,
        base_url: str,
        entitlement_evidence_sha256: str,
    ) -> Self:
        if base_url != CODING_PLAN_BASE_URL:
            raise ValueError("profile base URL is not the authorized Coding Plan base")
        if entitlement_evidence_sha256 != CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256:
            raise ValueError("Coding Plan entitlement evidence digest drifted")
        endpoint = f"{base_url}/chat/completions"
        if endpoint != CODING_PLAN_ENDPOINT:
            raise ValueError("Coding Plan completion endpoint derivation drifted")
        return cls()

    @model_validator(mode="after")
    def validate_authority_binding(self) -> Self:
        if (
            self.endpoint != f"{self.base_url}/chat/completions"
            or self.entitlement_evidence_sha256 != CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256
        ):
            raise ValueError("Coding Plan configuration authority drifted")
        return self


class NvidiaMinimaxProfileMaterializationConfig(StrictContract):
    """Sentinel-bounded NVIDIA MiniMax-M3 text response contract."""

    schema_version: Literal["itda.nvidia-minimax-profile-materialization-config.v3"] = (
        "itda.nvidia-minimax-profile-materialization-config.v3"
    )
    endpoint: Literal["https://integrate.api.nvidia.com/v1/chat/completions"] = (
        "https://integrate.api.nvidia.com/v1/chat/completions"
    )
    model: Literal["minimaxai/minimax-m3"] = "minimaxai/minimax-m3"
    provider_lane: Literal["NVIDIA_NIM_API"] = "NVIDIA_NIM_API"
    authorization_scheme: Literal["Bearer"] = "Bearer"
    temperature: Annotated[float, Field(strict=True, ge=0.0, le=0.0)] = 0.0
    top_p: Literal[None] = None
    top_p_policy: Literal["OMITTED_PROVIDER_DEFAULT_0_95"] = "OMITTED_PROVIDER_DEFAULT_0_95"
    max_tokens: Literal[8192] = 8192
    stream: Literal[False] = False
    seed: Literal[0] = 0
    thinking_mode: Literal["disabled"] = "disabled"
    output_contract: Literal["EXACT_SENTINEL_BOUNDED_JSON_OBJECT"] = (
        "EXACT_SENTINEL_BOUNDED_JSON_OBJECT"
    )
    json_start_sentinel: Literal["<<<ITDA_PROFILE_JSON_V3_START_4F3A6C91>>>"] = (
        "<<<ITDA_PROFILE_JSON_V3_START_4F3A6C91>>>"
    )
    json_end_sentinel: Literal["<<<ITDA_PROFILE_JSON_V3_END_9B7D2E65>>>"] = (
        "<<<ITDA_PROFILE_JSON_V3_END_9B7D2E65>>>"
    )
    bounded_json_max_bytes: Literal[65_536] = 65_536
    sentinel_policy: Literal["UNIQUE_ORDERED_WHITESPACE_OUTSIDE_ONLY"] = (
        "UNIQUE_ORDERED_WHITESPACE_OUTSIDE_ONLY"
    )
    prompt_injection_policy: Literal["EVIDENCE_IS_DATA_NEVER_INSTRUCTIONS"] = (
        "EVIDENCE_IS_DATA_NEVER_INSTRUCTIONS"
    )
    response_format_policy: Literal["OMITTED_UNDOCUMENTED_FOR_EXACT_MODEL"] = (
        "OMITTED_UNDOCUMENTED_FOR_EXACT_MODEL"
    )
    temperature_rationale: Literal["LOWER_TEMPERATURE_REDUCES_SAMPLING_VARIANCE"] = (
        "LOWER_TEMPERATURE_REDUCES_SAMPLING_VARIANCE"
    )
    thinking_mode_rationale: Literal["NO_THINK_PREVENTS_REASONING_PROSE"] = (
        "NO_THINK_PREVENTS_REASONING_PROSE"
    )
    output_contract_rationale: Literal["TEXT_OUTPUT_WITH_LOCAL_SENTINEL_AND_SCHEMA_VALIDATION"] = (
        "TEXT_OUTPUT_WITH_LOCAL_SENTINEL_AND_SCHEMA_VALIDATION"
    )
    connect_seconds: Literal[10] = 10
    pool_seconds: Literal[10] = 10
    write_seconds: Literal[30] = 30
    read_seconds: Literal[240] = 240
    attempt_deadline_seconds: Literal[300] = 300
    concurrency: Literal[1] = 1
    follow_redirects: Literal[False] = False
    trust_env: Literal[False] = False
    max_http_attempts: Literal[30] = 30
    authority_sha256: Sha256 = NVIDIA_AUTHORITY_SHA256

    @model_validator(mode="after")
    def validate_authority_binding(self) -> Self:
        if (
            self.endpoint != NVIDIA_PROFILE_ENDPOINT
            or self.model != NVIDIA_PROFILE_MODEL
            or self.provider_lane != NVIDIA_PROVIDER_LANE
            or self.authority_sha256 != NVIDIA_AUTHORITY_SHA256
        ):
            raise ValueError("NVIDIA configuration authority drifted")
        return self


class DemoSourceEvidence(StrictContract):
    evidence_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    source_kind: SourceKind
    source_sha256: Sha256
    span_sha256: Sha256
    text: Annotated[str, Field(strict=True, min_length=1, max_length=100_000, repr=False)]


class QualifiedImageCapability(StrictContract):
    image_ref: Annotated[str, Field(strict=True, pattern=r"^selected-image:[0-9a-f]{64}$")]
    image_sha256: Sha256
    selection_manifest_sha256: Sha256
    rights_manifest_sha256: Sha256
    display_authorized: Literal[True]


class DemoSourceBundle(StrictContract):
    schema_version: Literal["itda.demo-source-bundle.v1"]
    place_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    split: Literal["DEV"]
    sources: Annotated[tuple[DemoSourceEvidence, ...], Field(min_length=1, max_length=8)]
    optional_image: QualifiedImageCapability | None
    source_inventory_sha256: Sha256
    source_bundle_sha256: Sha256

    @model_validator(mode="before")
    @classmethod
    def reject_protected_inputs(cls, value: object) -> object:
        _reject_forbidden_keys(value)
        return value

    @model_validator(mode="after")
    def validate_bundle(self) -> Self:
        if self.split != "DEV":
            raise ValueError("profile materialization accepts DEV only")
        ids = tuple(source.evidence_id for source in self.sources)
        if len(ids) != len(set(ids)):
            raise ValueError("source evidence ids must be unique")
        if not {source.source_kind for source in self.sources} <= {
            "TOUR_API_DESCRIPTION",
            "ODII_TRANSCRIPT",
        }:
            raise ValueError("source kind is not authorized")
        _require_self_digest(self, digest_field="source_bundle_sha256")
        return self


class DemoProfileRequest(StrictContract):
    schema_version: Literal["itda.demo-profile-request.v1"]
    place_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    source_bundle_sha256: Sha256
    evidence_inventory_sha256: Sha256
    prompt_version: Literal["phase5-demo-profile.v1"]
    prompt_sha256: Sha256
    profile_schema_sha256: Sha256
    config_sha256: Sha256
    pricing_snapshot_sha256: Sha256
    image_ref: str | None = None
    request_sha256: Sha256

    @model_validator(mode="after")
    def validate_digest(self) -> Self:
        if self.pricing_snapshot_sha256 != PRICING_SNAPSHOT_SHA256:
            raise ValueError("request pricing snapshot digest drifted")
        _require_self_digest(self, digest_field="request_sha256")
        return self


class DemoModelDerivedProfile(StrictContract):
    schema_version: Literal["itda.demo-model-derived-profile.v1"]
    analysis_origin: Literal["DEMO_MODEL_DERIVED"]
    place_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    split: Literal["DEV"]
    axis_scores: dict[AxisId, Annotated[int, Field(strict=True, ge=0, le=100)]]
    subattributes: dict[
        Annotated[str, Field(strict=True, pattern=r"^(?:H|I|R)[1-4]$")],
        Annotated[int, Field(strict=True, ge=0, le=4)],
    ]
    mismatch_traits: dict[
        Annotated[str, Field(strict=True, pattern=r"^M[1-6]$")],
        Annotated[int, Field(strict=True, ge=0, le=100)],
    ]
    evidence_ids: Annotated[tuple[str, ...], Field(min_length=1, max_length=32)]
    confidence: Annotated[int, Field(strict=True, ge=0, le=100)]
    publishable: Literal[True]
    model: Literal["glm-5v-turbo"]
    prompt_version: Literal["phase5-demo-profile.v1"]
    prompt_sha256: Sha256
    profile_schema_sha256: Sha256
    config_sha256: Sha256
    source_bundle_sha256: Sha256
    evidence_inventory_sha256: Sha256
    request_sha256: Sha256
    response_sha256: Sha256
    pricing_snapshot_sha256: Sha256
    created_at: datetime
    profile_sha256: Sha256

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="created_at")

    @model_validator(mode="after")
    def validate_complete_profile(self, info: ValidationInfo) -> Self:
        if set(self.axis_scores) != set(_AXIS_ORDER):
            raise ValueError("axis scores require exact H, E, R inventory")
        if set(self.subattributes) != set(_SUBATTRIBUTE_ORDER):
            raise ValueError("subattributes require exact H1-H4, I1-I4, R1-R4 inventory")
        if set(self.mismatch_traits) != set(_MISMATCH_ORDER):
            raise ValueError("mismatch traits require exact M1-M6 inventory")
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("profile evidence ids must be unique")
        if self.pricing_snapshot_sha256 != PRICING_SNAPSHOT_SHA256:
            raise ValueError("profile pricing snapshot digest drifted")
        known = (info.context or {}).get("known_evidence_ids")
        if known is not None and not set(self.evidence_ids) <= set(known):
            raise ValueError("profile references unknown evidence")
        _require_self_digest(self, digest_field="profile_sha256")
        return self


class NvidiaMinimaxModelDerivedProfile(StrictContract):
    """NVIDIA-specific profile contract; historical Z.ai profiles stay unchanged."""

    schema_version: Literal[
        "itda.nvidia-minimax-model-derived-profile.v4",
        "itda.nvidia-minimax-model-derived-profile.v5",
    ]
    analysis_origin: Literal["DEMO_MODEL_DERIVED"]
    place_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    split: Literal["DEV"]
    axis_scores: dict[AxisId, Annotated[int, Field(strict=True, ge=0, le=100)]]
    subattributes: dict[
        Annotated[str, Field(strict=True, pattern=r"^(?:H|I|R)[1-4]$")],
        Annotated[int, Field(strict=True, ge=0, le=4)],
    ]
    mismatch_traits: dict[
        Annotated[str, Field(strict=True, pattern=r"^M[1-6]$")],
        Annotated[int, Field(strict=True, ge=0, le=100)],
    ]
    evidence_justifications: dict[
        Annotated[str, Field(strict=True, pattern=r"^(?:[HER]|[HIR][1-4]|M[1-6])$")],
        Annotated[tuple[str, ...], Field(min_length=1, max_length=8)],
    ]
    evidence_ids: Annotated[tuple[str, ...], Field(min_length=1, max_length=32)]
    confidence: Annotated[int, Field(strict=True, ge=0, le=100)]
    publishable: Literal[True]
    model: Literal["minimaxai/minimax-m3"]
    provider_lane: Literal["NVIDIA_NIM_API"]
    endpoint: Literal["https://integrate.api.nvidia.com/v1/chat/completions"]
    prompt_version: Literal[
        "phase5-demo-profile-sentinel-json.v4",
        "phase5-demo-profile-sentinel-json.v5",
    ]
    prompt_sha256: Sha256
    profile_schema_sha256: Sha256
    config_sha256: Sha256
    authority_sha256: Sha256
    source_bundle_sha256: Sha256
    evidence_inventory_sha256: Sha256
    request_sha256: Sha256
    response_sha256: Sha256
    created_at: datetime
    profile_sha256: Sha256

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="created_at")

    @model_validator(mode="after")
    def validate_complete_profile(self, info: ValidationInfo) -> Self:
        expected_lineage = {
            "itda.nvidia-minimax-model-derived-profile.v4": (
                "phase5-demo-profile-sentinel-json.v4",
                None,
            ),
            "itda.nvidia-minimax-model-derived-profile.v5": (
                "phase5-demo-profile-sentinel-json.v5",
                NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS["prompt_sha256"],
            ),
        }
        prompt_version, prompt_sha256 = expected_lineage[self.schema_version]
        if self.prompt_version != prompt_version or (
            prompt_sha256 is not None and self.prompt_sha256 != prompt_sha256
        ):
            raise ValueError("NVIDIA profile schema/prompt lineage drifted")
        if set(self.axis_scores) != set(_AXIS_ORDER):
            raise ValueError("axis scores require exact H, E, R inventory")
        if set(self.subattributes) != set(_SUBATTRIBUTE_ORDER):
            raise ValueError("subattributes require exact H1-H4, I1-I4, R1-R4 inventory")
        if set(self.mismatch_traits) != set(_MISMATCH_ORDER):
            raise ValueError("mismatch traits require exact M1-M6 inventory")
        expected_justifications = set(_AXIS_ORDER) | set(_SUBATTRIBUTE_ORDER) | set(_MISMATCH_ORDER)
        if set(self.evidence_justifications) != expected_justifications:
            raise ValueError("NVIDIA profile requires evidence justification for every score")
        if any(
            not set(evidence_ids) <= set(self.evidence_ids)
            for evidence_ids in self.evidence_justifications.values()
        ):
            raise ValueError("score justification references undeclared profile evidence")
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("profile evidence ids must be unique")
        if self.authority_sha256 != NVIDIA_AUTHORITY_SHA256:
            raise ValueError("NVIDIA profile authority drifted")
        known = (info.context or {}).get("known_evidence_ids")
        if known is not None and not set(self.evidence_ids) <= set(known):
            raise ValueError("profile references unknown evidence")
        _require_self_digest(self, digest_field="profile_sha256")
        return self


class NvidiaLocalProfileLineage(StrictContract):
    """Exact provider-input lineage embedded in a local classification artifact."""

    prompt_version: Literal[
        "phase5-demo-profile-sentinel-json.v4",
        "phase5-demo-profile-sentinel-json.v5",
    ]
    prompt_sha256: Sha256
    profile_schema_sha256: Sha256
    config_sha256: Sha256
    authority_sha256: Sha256
    resume_authority_sha256: Sha256 | None = None
    source_bundle_sha256: Sha256
    evidence_inventory_sha256: Sha256
    request_sha256: Sha256
    evidence_ids: Annotated[list[str], Field(min_length=1)]
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="created_at")

    @model_validator(mode="after")
    def validate_evidence_ids(self) -> Self:
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("NVIDIA local lineage evidence IDs must be unique")
        if self.authority_sha256 != NVIDIA_AUTHORITY_SHA256:
            raise ValueError("NVIDIA local lineage authority drifted")
        if self.prompt_version == "phase5-demo-profile-sentinel-json.v4":
            if self.prompt_sha256 != _NVIDIA_V4_PROMPT_SHA256:
                raise ValueError("NVIDIA V4 local lineage prompt digest drifted")
            if self.profile_schema_sha256 != _NVIDIA_V4_PROFILE_SCHEMA_SHA256:
                raise ValueError("NVIDIA V4 local lineage profile schema drifted")
            if self.config_sha256 != _NVIDIA_CONFIG_SHA256:
                raise ValueError("NVIDIA V4 local lineage configuration drifted")
            if self.resume_authority_sha256 is not None:
                raise ValueError("NVIDIA V4 local lineage forbids resume authority")
        else:
            if self.prompt_sha256 != _NVIDIA_V5_PROMPT_SHA256:
                raise ValueError("NVIDIA V5 local lineage prompt digest drifted")
            if self.profile_schema_sha256 != _NVIDIA_V5_PROFILE_SCHEMA_SHA256:
                raise ValueError("NVIDIA V5 local lineage profile schema drifted")
            if self.config_sha256 != _NVIDIA_CONFIG_SHA256:
                raise ValueError("NVIDIA V5 local lineage configuration drifted")
            if self.resume_authority_sha256 not in {
                NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_SHA256,
                NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_SHA256,
                NVIDIA_V5_ATTEMPT8_RESUME_AUTHORITY_SHA256,
            }:
                raise ValueError("NVIDIA V5 local lineage resume authority drifted")
        return self


class NvidiaProfileRecommendationClassification(StrictContract):
    """Digest-bound local eligibility receipt; never mutates frozen V4/V5 schema."""

    schema_version: Literal["itda.nvidia-profile-recommendation-classification.v1"] = (
        "itda.nvidia-profile-recommendation-classification.v1"
    )
    profile_sha256: Sha256
    response_sha256: Sha256
    lineage: NvidiaLocalProfileLineage
    lineage_sha256: Sha256
    confidence: Annotated[int, Field(strict=True, ge=0, le=100)]
    recommendation_eligible: StrictBool
    recommendation_eligibility_reason: Literal["ELIGIBLE", "LOW_CONFIDENCE"]
    release_eligible: Literal[False] = False
    classification_sha256: Sha256

    @model_validator(mode="after")
    def validate_classification(self) -> Self:
        if (
            canonical_sha256(self.lineage.model_dump(mode="json", exclude_none=True))
            != self.lineage_sha256
        ):
            raise ValueError("NVIDIA recommendation classification lineage drifted")
        expected_eligible = self.confidence >= 70
        expected_reason = "ELIGIBLE" if expected_eligible else "LOW_CONFIDENCE"
        if (
            self.recommendation_eligible is not expected_eligible
            or self.recommendation_eligibility_reason != expected_reason
        ):
            raise ValueError("NVIDIA recommendation eligibility classification drifted")
        _require_self_digest(self, digest_field="classification_sha256")
        return self


class Phase5RecoveryProfileClassification(StrictContract):
    """Additive D-28/D-31 classification for a current recovery profile.

    The historical NVIDIA local-classification contract above remains unchanged.
    This successor carries only policy/relation identity and values derived from
    the returned profile; it cannot carry provider or caller pass flags.
    """

    schema_version: Literal["itda.phase5-recovery-profile-classification.v1"] = (
        "itda.phase5-recovery-profile-classification.v1"
    )
    profile_sha256: Sha256
    confidence: Annotated[int, Field(strict=True, ge=0, le=100)]
    confidence_band: Literal[
        "EVIDENCE_AUDIT_ONLY",
        "EVIDENCE_LIMITED_MISMATCH_SUPPRESSED",
        "EVIDENCE_LIMITED_MISMATCH_AVAILABLE",
        "EVIDENCE_SUPPORTED",
    ]
    recommendation_eligible: StrictBool
    mismatch_guidance_eligible: StrictBool
    policy_sha256: Sha256
    hard_duplicate_adjudication_sha256: Sha256 = HARD_DUPLICATE_ADJUDICATION_SHA256
    cannot_coappear_authority_sha256: Sha256
    classification_sha256: Sha256

    @model_validator(mode="after")
    def validate_recovery_classification(self) -> Self:
        policy = CANONICAL_PHASE5_RECOVERY_POLICY
        if self.policy_sha256 != policy.policy_sha256:
            raise ValueError("Phase 5 recovery policy identity drifted")
        if self.hard_duplicate_adjudication_sha256 != policy.hard_duplicate_adjudication_sha256:
            raise ValueError("Phase 5 hard-duplicate identity drifted")
        if (
            self.cannot_coappear_authority_sha256
            != policy.cannot_coappear_authority.authority_sha256
        ):
            raise ValueError("Phase 5 cannot-coappear identity drifted")
        if self.confidence < policy.candidate_confidence_min:
            expected_band = "EVIDENCE_AUDIT_ONLY"
        elif self.confidence < policy.mismatch_guidance_confidence_min:
            expected_band = "EVIDENCE_LIMITED_MISMATCH_SUPPRESSED"
        elif self.confidence < policy.ordinary_information_confidence_min:
            expected_band = "EVIDENCE_LIMITED_MISMATCH_AVAILABLE"
        else:
            expected_band = "EVIDENCE_SUPPORTED"
        if self.confidence_band != expected_band:
            raise ValueError("Phase 5 confidence band drifted")
        if self.recommendation_eligible != (self.confidence >= policy.candidate_confidence_min):
            raise ValueError("Phase 5 recommendation candidacy drifted")
        if self.mismatch_guidance_eligible != (
            self.confidence >= policy.mismatch_guidance_confidence_min
        ):
            raise ValueError("Phase 5 mismatch guidance eligibility drifted")
        _require_self_digest(self, digest_field="classification_sha256")
        return self


class NvidiaLocalProfileClassificationArtifact(StrictContract):
    """Stored local-only profile plus its digest-bound recommendation classification."""

    schema_version: Literal["itda.nvidia-local-profile-classification-artifact.v1"] = (
        "itda.nvidia-local-profile-classification-artifact.v1"
    )
    profile: NvidiaMinimaxModelDerivedProfile
    classification: NvidiaProfileRecommendationClassification
    artifact_sha256: Sha256

    @model_validator(mode="after")
    def validate_artifact(self) -> Self:
        if self.profile.profile_sha256 != self.classification.profile_sha256:
            raise ValueError("NVIDIA local classification profile lineage drifted")
        if self.profile.response_sha256 != self.classification.response_sha256:
            raise ValueError("NVIDIA local classification response lineage drifted")
        if self.profile.confidence != self.classification.confidence:
            raise ValueError("NVIDIA local classification confidence drifted")
        lineage = self.classification.lineage
        for field_name in (
            "prompt_version",
            "prompt_sha256",
            "profile_schema_sha256",
            "config_sha256",
            "authority_sha256",
            "source_bundle_sha256",
            "evidence_inventory_sha256",
            "request_sha256",
            "created_at",
        ):
            if getattr(self.profile, field_name) != getattr(lineage, field_name):
                raise ValueError("NVIDIA local classification embedded lineage drifted")
        if self.profile.evidence_ids != tuple(lineage.evidence_ids):
            raise ValueError("NVIDIA local classification evidence lineage drifted")
        _require_self_digest(self, digest_field="artifact_sha256")
        return self


class DemoProfileAttempt(StrictContract):
    schema_version: Literal["itda.demo-profile-attempt.v1"] = "itda.demo-profile-attempt.v1"
    place_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    attempt_number: Annotated[int, Field(strict=True, ge=1, le=30)]
    outcome: Literal[
        "VALIDATED",
        "TRANSPORT_ERROR",
        "HTTP_ERROR",
        "RESPONSE_INVALID",
        "ATTEMPT_DEADLINE_EXCEEDED",
        "COST_BUDGET_EXHAUSTED",
    ]
    retry: StrictBool
    http_status: Annotated[int, Field(strict=True, ge=100, le=599)] | None
    error_code: Annotated[str, Field(strict=True, min_length=1, max_length=100)] | None
    returned_model: Annotated[str, Field(strict=True, min_length=1, max_length=100)] | None
    finish_reason: Annotated[str, Field(strict=True, min_length=1, max_length=40)] | None
    response_sha256: Sha256 | None
    usage: ProviderTokenUsage | None
    reservation_micro_usd: Literal[248_192]
    committed_micro_usd: Annotated[int, Field(strict=True, ge=0)]
    refund_micro_usd: Annotated[int, Field(strict=True, ge=0)]
    remaining_cap_micro_usd: Annotated[int, Field(strict=True, ge=0, le=RERUN_COST_CAP_MICRO_USD)]
    duration_ms: Annotated[int, Field(strict=True, ge=0, le=300_100)]
    pricing_snapshot_sha256: Sha256
    attempt_sha256: Sha256

    @model_validator(mode="after")
    def validate_attempt(self) -> Self:
        if self.pricing_snapshot_sha256 != PRICING_SNAPSHOT_SHA256:
            raise ValueError("attempt pricing snapshot digest drifted")
        if self.outcome == "VALIDATED":
            if (
                any(
                    value is None
                    for value in (
                        self.http_status,
                        self.returned_model,
                        self.finish_reason,
                        self.response_sha256,
                        self.usage,
                    )
                )
                or self.error_code is not None
                or self.http_status != 200
            ):
                raise ValueError("validated attempt requires complete safe lineage")
        elif self.error_code is None:
            raise ValueError("failed attempt requires a safe error code")
        _require_self_digest(self, digest_field="attempt_sha256")
        return self


class CodingPlanProfileAttempt(StrictContract):
    schema_version: Literal["itda.coding-plan-profile-attempt.v1"] = (
        "itda.coding-plan-profile-attempt.v1"
    )
    place_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    attempt_number: Annotated[int, Field(strict=True, ge=1, le=30)]
    outcome: Literal[
        "VALIDATED",
        "TRANSPORT_ERROR",
        "HTTP_ERROR",
        "RESPONSE_INVALID",
        "ATTEMPT_DEADLINE_EXCEEDED",
        "ATTEMPT_BUDGET_EXHAUSTED",
    ]
    retry: StrictBool
    http_status: Annotated[int, Field(strict=True, ge=100, le=599)] | None
    error_code: Annotated[str, Field(strict=True, min_length=1, max_length=100)] | None
    returned_model: Annotated[str, Field(strict=True, min_length=1, max_length=100)] | None
    finish_reason: Annotated[str, Field(strict=True, min_length=1, max_length=40)] | None
    response_sha256: Sha256 | None
    usage: ProviderTokenUsage | None
    provider_lane: Literal["CODING_PLAN_SUBSCRIPTION"] = "CODING_PLAN_SUBSCRIPTION"
    endpoint: Literal["https://api.z.ai/api/coding/paas/v4/chat/completions"] = (
        "https://api.z.ai/api/coding/paas/v4/chat/completions"
    )
    model: Literal["glm-5v-turbo"] = "glm-5v-turbo"
    accounting_mode: Literal["CODING_PLAN_WEIGHT"] = "CODING_PLAN_WEIGHT"
    entitlement_evidence_sha256: Sha256 = CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256
    model_weight: Literal[1] = 1
    subscription_attempt_weight: Literal[1] = 1
    subscription_cumulative_weight: Annotated[int, Field(strict=True, ge=1, le=30)]
    duration_ms: Annotated[int, Field(strict=True, ge=0, le=300_100)]
    attempt_sha256: Sha256

    @model_validator(mode="after")
    def validate_attempt(self) -> Self:
        if self.entitlement_evidence_sha256 != CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256:
            raise ValueError("Coding Plan attempt evidence drifted")
        if self.outcome == "VALIDATED":
            if (
                any(
                    value is None
                    for value in (
                        self.http_status,
                        self.returned_model,
                        self.finish_reason,
                        self.response_sha256,
                        self.usage,
                    )
                )
                or self.error_code is not None
                or self.http_status != 200
            ):
                raise ValueError("validated Coding Plan attempt requires complete safe lineage")
        elif self.error_code is None:
            raise ValueError("failed Coding Plan attempt requires a safe error code")
        _require_self_digest(self, digest_field="attempt_sha256")
        return self


class NvidiaMinimaxProfileAttempt(StrictContract):
    schema_version: Literal["itda.nvidia-minimax-profile-attempt.v3"] = (
        "itda.nvidia-minimax-profile-attempt.v3"
    )
    place_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    # Attempts 31-34 are reserved exclusively for the separately authorized
    # attempt-5-retaining V5 continuation. Legacy receipt validators retain
    # their narrower inventories.
    attempt_number: Annotated[int, Field(strict=True, ge=1, le=34)]
    outcome: Literal[
        "VALIDATED",
        "TRANSPORT_ERROR",
        "HTTP_ERROR",
        "RESPONSE_INVALID",
        "ATTEMPT_DEADLINE_EXCEEDED",
        "ATTEMPT_BUDGET_EXHAUSTED",
    ]
    retry: StrictBool
    http_status: Annotated[int, Field(strict=True, ge=100, le=599)] | None
    error_code: Annotated[str, Field(strict=True, min_length=1, max_length=100)] | None
    error_reason: Annotated[str, Field(strict=True, min_length=1, max_length=300)] | None
    returned_model: Annotated[str, Field(strict=True, min_length=1, max_length=100)] | None
    finish_reason: Annotated[str, Field(strict=True, min_length=1, max_length=40)] | None
    request_sha256: Sha256
    response_sha256: Sha256 | None
    usage: NvidiaProviderTokenUsage | None
    provider_lane: Literal["NVIDIA_NIM_API"] = "NVIDIA_NIM_API"
    endpoint: Literal["https://integrate.api.nvidia.com/v1/chat/completions"] = (
        "https://integrate.api.nvidia.com/v1/chat/completions"
    )
    model: Literal["minimaxai/minimax-m3"] = "minimaxai/minimax-m3"
    config_sha256: Sha256
    authority_sha256: Sha256 = NVIDIA_AUTHORITY_SHA256
    started_at: datetime
    completed_at: datetime
    duration_ms: Annotated[int, Field(strict=True, ge=0, le=300_100)]
    attempt_sha256: Sha256

    @field_validator("started_at", "completed_at")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="NVIDIA attempt timestamp")

    @model_validator(mode="after")
    def validate_attempt(self) -> Self:
        if self.authority_sha256 != NVIDIA_AUTHORITY_SHA256:
            raise ValueError("NVIDIA attempt authority drifted")
        if self.completed_at < self.started_at:
            raise ValueError("NVIDIA attempt timestamps are reversed")
        if self.outcome == "VALIDATED":
            if (
                any(
                    value is None
                    for value in (
                        self.http_status,
                        self.returned_model,
                        self.finish_reason,
                        self.response_sha256,
                        self.usage,
                    )
                )
                or self.error_code is not None
                or self.error_reason is not None
                or self.http_status != 200
            ):
                raise ValueError("validated NVIDIA attempt requires complete safe lineage")
        elif self.error_code is None:
            raise ValueError("failed NVIDIA attempt requires a safe error code")
        _require_self_digest(self, digest_field="attempt_sha256")
        return self


class DemoProfileMaterializationReceipt(StrictContract):
    schema_version: Literal["itda.demo-profile-materialization-receipt.v1"]
    status: Literal["COMPLETE_REPLAY_ONLY", "COMPLETE_UNACTIVATED"]
    analysis_origin: Literal["DEMO_MODEL_DERIVED"]
    profile_count: Literal[24]
    profile_sha256: Annotated[tuple[Sha256, ...], Field(min_length=24, max_length=24)]
    attempt_sha256: Annotated[tuple[Sha256, ...], Field(min_length=24, max_length=30)]
    pricing_snapshot_sha256: Sha256
    committed_cost_micro_usd: Annotated[int, Field(strict=True, ge=0, le=RERUN_COST_CAP_MICRO_USD)]
    outstanding_cost_micro_usd: Literal[0]
    run_cost_cap_micro_usd: Literal[5_000_000, 7_500_000] = 5_000_000
    prior_committed_lower_micro_usd: Annotated[int, Field(strict=True, ge=0)] = 0
    prior_committed_upper_micro_usd: Annotated[int, Field(strict=True, ge=0)] = 0
    cumulative_reservation_cap_micro_usd: Literal[5_000_000, 12_500_000] = 5_000_000
    rerun_authority_sha256: Sha256 | None = None
    generation_sha256: Sha256
    receipt_sha256: Sha256

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        if self.pricing_snapshot_sha256 != PRICING_SNAPSHOT_SHA256:
            raise ValueError("receipt pricing snapshot digest drifted")
        if len(set(self.profile_sha256)) != 24:
            raise ValueError("receipt requires 24 unique profile digests")
        if len(set(self.attempt_sha256)) != len(self.attempt_sha256):
            raise ValueError("receipt attempt digests must be unique")
        rerun_fields = (
            self.run_cost_cap_micro_usd,
            self.prior_committed_lower_micro_usd,
            self.prior_committed_upper_micro_usd,
            self.cumulative_reservation_cap_micro_usd,
            self.rerun_authority_sha256,
        )
        if self.rerun_authority_sha256 is None:
            if rerun_fields != (MAX_RUN_COST_MICRO_USD, 0, 0, MAX_RUN_COST_MICRO_USD, None):
                raise ValueError("ordinary receipt cannot claim rerun authority")
        elif rerun_fields != (
            RERUN_COST_CAP_MICRO_USD,
            PRIOR_COMMITTED_LOWER_MICRO_USD,
            PRIOR_COMMITTED_UPPER_MICRO_USD,
            CUMULATIVE_RERUN_CAP_MICRO_USD,
            RERUN_AUTHORITY_SHA256,
        ):
            raise ValueError("rerun receipt authority or cumulative arithmetic drifted")
        if self.committed_cost_micro_usd > self.run_cost_cap_micro_usd:
            raise ValueError("receipt committed cost exceeds its bound run cap")
        digest_payload = self.model_dump(mode="json", exclude={"receipt_sha256"})
        valid_digests = {canonical_sha256(digest_payload)}
        if self.rerun_authority_sha256 is None:
            for field_name in (
                "run_cost_cap_micro_usd",
                "prior_committed_lower_micro_usd",
                "prior_committed_upper_micro_usd",
                "cumulative_reservation_cap_micro_usd",
                "rerun_authority_sha256",
            ):
                digest_payload.pop(field_name, None)
            valid_digests.add(canonical_sha256(digest_payload))
        if self.receipt_sha256 not in valid_digests:
            raise ValueError("receipt_sha256 does not match canonical content")
        return self


class CodingPlanProfileMaterializationReceipt(StrictContract):
    schema_version: Literal["itda.coding-plan-profile-materialization-receipt.v1"] = (
        "itda.coding-plan-profile-materialization-receipt.v1"
    )
    status: Literal["COMPLETE_UNACTIVATED"] = "COMPLETE_UNACTIVATED"
    analysis_origin: Literal["DEMO_MODEL_DERIVED"] = "DEMO_MODEL_DERIVED"
    profile_count: Literal[24]
    profile_sha256: Annotated[tuple[Sha256, ...], Field(min_length=24, max_length=24)]
    attempt_sha256: Annotated[tuple[Sha256, ...], Field(min_length=24, max_length=30)]
    provider_lane: Literal["CODING_PLAN_SUBSCRIPTION"] = "CODING_PLAN_SUBSCRIPTION"
    base_url: Literal["https://api.z.ai/api/coding/paas/v4"] = "https://api.z.ai/api/coding/paas/v4"
    endpoint: Literal["https://api.z.ai/api/coding/paas/v4/chat/completions"] = (
        "https://api.z.ai/api/coding/paas/v4/chat/completions"
    )
    model: Literal["glm-5v-turbo"] = "glm-5v-turbo"
    accounting_mode: Literal["CODING_PLAN_WEIGHT"] = "CODING_PLAN_WEIGHT"
    entitlement_evidence_sha256: Sha256 = CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256
    model_weight: Literal[1] = 1
    subscription_attempt_count: Annotated[int, Field(strict=True, ge=24, le=30)]
    subscription_total_weight: Annotated[int, Field(strict=True, ge=24, le=30)]
    coding_plan_authority_sha256: Sha256 = CODING_PLAN_AUTHORITY_SHA256
    generation_sha256: Sha256
    receipt_sha256: Sha256

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        if (
            self.endpoint != f"{self.base_url}/chat/completions"
            or self.entitlement_evidence_sha256 != CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256
            or self.coding_plan_authority_sha256 != CODING_PLAN_AUTHORITY_SHA256
        ):
            raise ValueError("Coding Plan receipt authority binding drifted")
        if len(set(self.profile_sha256)) != 24:
            raise ValueError("receipt requires 24 unique profile digests")
        if len(set(self.attempt_sha256)) != len(self.attempt_sha256):
            raise ValueError("receipt attempt digests must be unique")
        if self.subscription_attempt_count != len(self.attempt_sha256):
            raise ValueError("Coding Plan attempt count does not match receipt inventory")
        if self.subscription_total_weight != self.subscription_attempt_count * self.model_weight:
            raise ValueError("Coding Plan total weight arithmetic drifted")
        _require_self_digest(self, digest_field="receipt_sha256")
        return self


class NvidiaMinimaxProfileMaterializationReceipt(StrictContract):
    schema_version: Literal[
        "itda.nvidia-minimax-profile-materialization-receipt.v3",
        "itda.nvidia-minimax-profile-materialization-receipt.v4",
    ] = "itda.nvidia-minimax-profile-materialization-receipt.v3"
    status: Literal["COMPLETE_UNACTIVATED"] = "COMPLETE_UNACTIVATED"
    analysis_origin: Literal["DEMO_MODEL_DERIVED"] = "DEMO_MODEL_DERIVED"
    profile_count: Literal[24]
    profile_sha256: Annotated[tuple[Sha256, ...], Field(min_length=24, max_length=24)]
    attempt_sha256: Annotated[tuple[Sha256, ...], Field(min_length=24, max_length=30)]
    provider_lane: Literal["NVIDIA_NIM_API"] = "NVIDIA_NIM_API"
    endpoint: Literal["https://integrate.api.nvidia.com/v1/chat/completions"] = (
        "https://integrate.api.nvidia.com/v1/chat/completions"
    )
    model: Literal["minimaxai/minimax-m3"] = "minimaxai/minimax-m3"
    temperature: Annotated[float, Field(strict=True, ge=0.0, le=0.0)] = 0.0
    top_p: Literal[None] = None
    top_p_policy: Literal["OMITTED_PROVIDER_DEFAULT_0_95"] = "OMITTED_PROVIDER_DEFAULT_0_95"
    max_tokens: Literal[8192] = 8192
    stream: Literal[False] = False
    seed: Literal[0] = 0
    thinking_mode: Literal["disabled"] = "disabled"
    output_contract: Literal["EXACT_SENTINEL_BOUNDED_JSON_OBJECT"] = (
        "EXACT_SENTINEL_BOUNDED_JSON_OBJECT"
    )
    json_start_sentinel: Literal["<<<ITDA_PROFILE_JSON_V3_START_4F3A6C91>>>"] = (
        "<<<ITDA_PROFILE_JSON_V3_START_4F3A6C91>>>"
    )
    json_end_sentinel: Literal["<<<ITDA_PROFILE_JSON_V3_END_9B7D2E65>>>"] = (
        "<<<ITDA_PROFILE_JSON_V3_END_9B7D2E65>>>"
    )
    bounded_json_max_bytes: Literal[65_536] = 65_536
    sentinel_policy: Literal["UNIQUE_ORDERED_WHITESPACE_OUTSIDE_ONLY"] = (
        "UNIQUE_ORDERED_WHITESPACE_OUTSIDE_ONLY"
    )
    prompt_injection_policy: Literal["EVIDENCE_IS_DATA_NEVER_INSTRUCTIONS"] = (
        "EVIDENCE_IS_DATA_NEVER_INSTRUCTIONS"
    )
    response_format_policy: Literal["OMITTED_UNDOCUMENTED_FOR_EXACT_MODEL"] = (
        "OMITTED_UNDOCUMENTED_FOR_EXACT_MODEL"
    )
    temperature_rationale: Literal["LOWER_TEMPERATURE_REDUCES_SAMPLING_VARIANCE"] = (
        "LOWER_TEMPERATURE_REDUCES_SAMPLING_VARIANCE"
    )
    thinking_mode_rationale: Literal["NO_THINK_PREVENTS_REASONING_PROSE"] = (
        "NO_THINK_PREVENTS_REASONING_PROSE"
    )
    output_contract_rationale: Literal["TEXT_OUTPUT_WITH_LOCAL_SENTINEL_AND_SCHEMA_VALIDATION"] = (
        "TEXT_OUTPUT_WITH_LOCAL_SENTINEL_AND_SCHEMA_VALIDATION"
    )
    config_sha256: Sha256
    authority_sha256: Sha256 = NVIDIA_AUTHORITY_SHA256
    prompt_version: Literal[
        "phase5-demo-profile-sentinel-json.v4",
        "phase5-demo-profile-sentinel-json.v5",
    ] = "phase5-demo-profile-sentinel-json.v4"
    prompt_sha256: Sha256
    profile_schema_sha256: Sha256
    source_inventory_sha256: Sha256
    resume_authority_sha256: Sha256 | None
    predecessor_manifest_sha256: Sha256 | None
    validated_predecessor_count: Literal[0, 3, 13]
    remaining_member_count: Literal[11, 21, 24]
    validated_membership_sha256: Sha256 | None
    remaining_membership_sha256: Sha256 | None
    http_attempt_count: Annotated[int, Field(strict=True, ge=24, le=30)]
    generation_sha256: Sha256
    receipt_sha256: Sha256

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        expected_prompt_version = (
            "phase5-demo-profile-sentinel-json.v5"
            if self.schema_version == "itda.nvidia-minimax-profile-materialization-receipt.v4"
            else "phase5-demo-profile-sentinel-json.v4"
        )
        if self.prompt_version != expected_prompt_version or (
            expected_prompt_version == "phase5-demo-profile-sentinel-json.v5"
            and self.prompt_sha256 != NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS["prompt_sha256"]
        ):
            raise ValueError("NVIDIA receipt schema/prompt lineage drifted")
        if self.authority_sha256 != NVIDIA_AUTHORITY_SHA256:
            raise ValueError("NVIDIA receipt authority drifted")
        if len(set(self.profile_sha256)) != 24:
            raise ValueError("receipt requires 24 unique profile digests")
        if len(set(self.attempt_sha256)) != len(self.attempt_sha256):
            raise ValueError("receipt attempt digests must be unique")
        if self.http_attempt_count != len(self.attempt_sha256):
            raise ValueError("NVIDIA attempt count does not match receipt inventory")
        if self.resume_authority_sha256 is None:
            if any(
                value is not None
                for value in (
                    self.predecessor_manifest_sha256,
                    self.validated_membership_sha256,
                    self.remaining_membership_sha256,
                )
            ) or (self.validated_predecessor_count, self.remaining_member_count) != (0, 24):
                raise ValueError("fresh NVIDIA receipt contains resume lineage")
        elif self.resume_authority_sha256 == NVIDIA_RESUME_AUTHORITY_SHA256:
            if (
                self.predecessor_manifest_sha256 != NVIDIA_RESUME_PREDECESSOR_MANIFEST_SHA256
                or self.validated_predecessor_count != 3
                or self.remaining_member_count != 21
                or self.validated_membership_sha256
                != "150845a40818d1138478489988bd2f16a74c2b6a7938d733c5ab7fc27d8c04d3"
                or self.remaining_membership_sha256
                != "4376b46dfb100f38a643022d819c4e061b5da4be6ee2c3f3cb705036d559d150"
            ):
                raise ValueError("resumed NVIDIA receipt authority drifted")
        elif self.resume_authority_sha256 == NVIDIA_SECOND_RESUME_AUTHORITY_SHA256:
            if (
                self.predecessor_manifest_sha256 != NVIDIA_SECOND_RESUME_RECONCILIATION_SHA256
                or self.validated_predecessor_count != 13
                or self.remaining_member_count != 11
                or self.validated_membership_sha256
                != NVIDIA_SECOND_RESUME_VALIDATED_MEMBERSHIP_SHA256
                or self.remaining_membership_sha256
                != NVIDIA_SECOND_RESUME_REMAINING_MEMBERSHIP_SHA256
            ):
                raise ValueError("second-resumed NVIDIA receipt authority drifted")
        elif self.resume_authority_sha256 == NVIDIA_V4_PROBE_RESUME_AUTHORITY_SHA256:
            if (
                self.predecessor_manifest_sha256
                != NVIDIA_V4_PROBE_RESUME_PREDECESSOR_MANIFEST_SHA256
                or self.validated_predecessor_count != 0
                or self.remaining_member_count != 24
                or self.validated_membership_sha256
                != NVIDIA_V4_PROBE_RESUME_VALIDATED_MEMBERSHIP_SHA256
                or self.remaining_membership_sha256
                != NVIDIA_V4_PROBE_RESUME_REMAINING_MEMBERSHIP_SHA256
            ):
                raise ValueError("v4 probe-resumed NVIDIA receipt authority drifted")
        elif self.resume_authority_sha256 == NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_SHA256:
            expected_predecessor = canonical_sha256(
                {
                    "attempt1": NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS[
                        "attempt1_root_manifest_sha256"
                    ],
                    "attempt2": NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS[
                        "attempt2_root_manifest_sha256"
                    ],
                }
            )
            if (
                self.schema_version != "itda.nvidia-minimax-profile-materialization-receipt.v4"
                or self.predecessor_manifest_sha256 != expected_predecessor
                or self.validated_predecessor_count != 0
                or self.remaining_member_count != 24
                or self.validated_membership_sha256
                != NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS["validated_membership_sha256"]
                or self.remaining_membership_sha256
                != NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS["remaining_membership_sha256"]
            ):
                raise ValueError("v5 two-probe-resumed NVIDIA receipt authority drifted")
        elif self.resume_authority_sha256 == NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_SHA256:
            if (
                self.schema_version != "itda.nvidia-minimax-profile-materialization-receipt.v4"
                or self.http_attempt_count != 27
                or self.predecessor_manifest_sha256
                != NVIDIA_V5_THREE_VALIDATED_RESUME_BINDINGS["predecessor_root_manifest_sha256"]
                or self.validated_predecessor_count != 3
                or self.remaining_member_count != 21
                or self.validated_membership_sha256
                != NVIDIA_V5_THREE_VALIDATED_RESUME_BINDINGS["validated_membership_sha256"]
                or self.remaining_membership_sha256
                != NVIDIA_V5_THREE_VALIDATED_RESUME_BINDINGS["remaining_membership_sha256"]
            ):
                raise ValueError("v5 three-validated-resumed NVIDIA receipt authority drifted")
        elif self.resume_authority_sha256 == NVIDIA_V5_ATTEMPT8_RESUME_AUTHORITY_SHA256:
            if (
                self.schema_version != "itda.nvidia-minimax-profile-materialization-receipt.v4"
                or self.http_attempt_count != 28
                or self.predecessor_manifest_sha256
                != NVIDIA_V5_ATTEMPT8_RESUME_BINDINGS["predecessor_root_manifest_sha256"]
                or self.validated_predecessor_count != 3
                or self.remaining_member_count != 21
                or self.validated_membership_sha256
                != NVIDIA_V5_ATTEMPT8_RESUME_BINDINGS["validated_membership_sha256"]
                or self.remaining_membership_sha256
                != NVIDIA_V5_ATTEMPT8_RESUME_BINDINGS["remaining_membership_sha256"]
            ):
                raise ValueError("v5 attempt8-resumed NVIDIA receipt authority drifted")
        else:
            raise ValueError("resumed NVIDIA receipt authority drifted")
        _require_self_digest(self, digest_field="receipt_sha256")
        return self


class PublicEvidenceExcerpt(StrictContract):
    """Source-bound contest-demo excerpt; never synthesized by the scorer."""

    evidence_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    source_kind: SourceKind
    source_label_ko: Annotated[str, Field(strict=True, min_length=1, max_length=100)]
    attribution_ko: Annotated[str, Field(strict=True, min_length=1, max_length=180)]
    provider: Annotated[str, Field(strict=True, min_length=1, max_length=40)]
    official_dataset_id: Annotated[str, Field(strict=True, min_length=1, max_length=80)]
    endpoint: Annotated[str, Field(strict=True, min_length=1, max_length=120)]
    contest_use_scope: Literal["noncommercial_contest_demo_evaluation"]
    contest_rights_qualified: Literal[True]
    commercial_production_rights_review_required: Literal[True]
    excerpt_ko: Annotated[str, Field(strict=True, min_length=20, max_length=240)]
    excerpt_sha256: Sha256
    source_sha256: Sha256
    span_sha256: Sha256
    source_authority_sha256: Sha256
    contest_rights_root_sha256: Sha256

    @model_validator(mode="after")
    def validate_source_bound_excerpt(self) -> Self:
        if self.excerpt_ko == "활성 공개 릴리스에 봉인된 근거입니다.":
            raise ValueError("generic public evidence placeholder is forbidden")
        if self.excerpt_sha256 != hashlib.sha256(self.excerpt_ko.encode("utf-8")).hexdigest():
            raise ValueError("public evidence excerpt digest drifted")
        return self


class PublicScoredProfile(StrictContract):
    """Bounded score/evidence projection safe for the public journey."""

    place_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    place_name_ko: Annotated[str, Field(strict=True, min_length=1, max_length=120)]
    duplicate_group_id: Annotated[
        str,
        Field(strict=True, pattern=r"^hard-duplicate-singleton:[0-9a-f]{64}$"),
    ]
    axis_scores: dict[AxisId, Annotated[int, Field(strict=True, ge=0, le=100)]]
    subattributes: dict[
        Annotated[str, Field(strict=True, pattern=r"^(?:H|I|R)[1-4]$")],
        Annotated[int, Field(strict=True, ge=0, le=4)],
    ]
    mismatch_traits: dict[
        Annotated[str, Field(strict=True, pattern=r"^M[1-6]$")],
        Annotated[int, Field(strict=True, ge=0, le=100)],
    ]
    evidence_ids: Annotated[tuple[str, ...], Field(min_length=1, max_length=32)]
    evidence_justifications: dict[
        Annotated[str, Field(strict=True, pattern=r"^(?:[HER]|[HIR][1-4]|M[1-6])$")],
        Annotated[tuple[str, ...], Field(min_length=1, max_length=8)],
    ]
    evidence_excerpts: Annotated[
        tuple[PublicEvidenceExcerpt, ...], Field(min_length=1, max_length=32)
    ]
    confidence: Annotated[int, Field(strict=True, ge=0, le=100)]
    publishable: Literal[True]
    publication_state: Literal["PUBLISHABLE", "LIMITED_INFORMATION", "EXCLUDED_MANUAL_REVIEW"]
    recommendation_eligible: StrictBool
    analysis_origin: Literal["DEMO_MODEL_DERIVED"]
    model: Literal["glm-5v-turbo", "minimaxai/minimax-m3"]
    prompt_version: Literal[
        "phase5-demo-profile.v1",
        "phase5-demo-profile-json.v2",
        "phase5-demo-profile-sentinel-json.v4",
        "phase5-demo-profile-sentinel-json.v5",
    ]
    profile_sha256: Sha256
    source_bundle_sha256: Sha256
    evidence_inventory_sha256: Sha256
    response_sha256: Sha256
    created_at: datetime
    projection_sha256: Sha256

    @field_validator("created_at")
    @classmethod
    def validate_public_created_at(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="created_at")

    @model_validator(mode="after")
    def validate_public_projection(self) -> Self:
        if set(self.axis_scores) != set(_AXIS_ORDER):
            raise ValueError("public axes require exact H, E, R inventory")
        if set(self.subattributes) != set(_SUBATTRIBUTE_ORDER):
            raise ValueError("public subattributes require exact inventory")
        if set(self.mismatch_traits) != set(_MISMATCH_ORDER):
            raise ValueError("public mismatch traits require exact inventory")
        if tuple(item.evidence_id for item in self.evidence_excerpts) != self.evidence_ids:
            raise ValueError("public evidence excerpts must match the exact evidence inventory")
        expected_justifications = set(_AXIS_ORDER) | set(_SUBATTRIBUTE_ORDER) | set(_MISMATCH_ORDER)
        if set(self.evidence_justifications) != expected_justifications:
            raise ValueError("public profile requires exact score justifications")
        if any(
            not set(evidence_ids) <= set(self.evidence_ids)
            for evidence_ids in self.evidence_justifications.values()
        ):
            raise ValueError("public score justification references unknown evidence")
        if self.model == "glm-5v-turbo":
            raise ValueError("GLM public profile schema has no sealed dimension authority")
        expected_state = (
            "PUBLISHABLE"
            if self.confidence >= 70
            else "LIMITED_INFORMATION"
            if self.confidence >= 55
            else "EXCLUDED_MANUAL_REVIEW"
        )
        if self.publication_state != expected_state:
            raise ValueError("public qualification state drifted from confidence policy")
        if self.recommendation_eligible != (self.publication_state == "PUBLISHABLE"):
            raise ValueError("public recommendation eligibility drifted from qualification")
        _require_self_digest(self, digest_field="projection_sha256")
        return self


class Phase5DemoReleaseCandidate(StrictContract):
    """Private immutable candidate reconstructed from one complete live generation."""

    schema_version: Literal["itda.phase5-demo-release-candidate.v2"] = (
        "itda.phase5-demo-release-candidate.v2"
    )
    state: Literal["BUILT_UNACTIVATED"] = "BUILT_UNACTIVATED"
    analysis_origin: Literal["DEMO_MODEL_DERIVED"] = "DEMO_MODEL_DERIVED"
    model: Literal["glm-5v-turbo"] = "glm-5v-turbo"
    prompt_version: Literal["phase5-demo-profile.v1"] = "phase5-demo-profile.v1"
    generation_sha256: Sha256
    generation_receipt_sha256: Sha256
    membership_sha256: Sha256
    hard_duplicate_adjudication_sha256: Sha256
    source_inventory_sha256: Sha256
    pricing_snapshot_sha256: Sha256
    committed_cost_micro_usd: Annotated[int, Field(strict=True, ge=0, le=RERUN_COST_CAP_MICRO_USD)]
    rerun_authority_sha256: Sha256 | None = None
    attempt_count: Annotated[int, Field(strict=True, ge=24, le=MAX_HTTP_ATTEMPTS)]
    retry_count: Annotated[int, Field(strict=True, ge=0, le=6)]
    profiles: Annotated[tuple[DemoModelDerivedProfile, ...], Field(min_length=24, max_length=24)]
    release_sha256: Sha256

    @model_validator(mode="after")
    def validate_release_candidate(self) -> Self:
        place_ids = tuple(profile.place_id for profile in self.profiles)
        if place_ids != tuple(sorted(place_ids)) or len(set(place_ids)) != 24:
            raise ValueError("release candidate requires exact canonical unique membership")
        if self.membership_sha256 != canonical_sha256(list(place_ids)):
            raise ValueError("release membership digest drifted")
        if self.hard_duplicate_adjudication_sha256 != HARD_DUPLICATE_ADJUDICATION_SHA256:
            raise ValueError("release hard-duplicate adjudication drifted")
        if self.pricing_snapshot_sha256 != PRICING_SNAPSHOT_SHA256:
            raise ValueError("release pricing snapshot digest drifted")
        _require_self_digest(self, digest_field="release_sha256")
        return self


class Phase5CodingPlanReleaseCandidate(StrictContract):
    """Private candidate bound to subscription authority and weighted attempts."""

    schema_version: Literal["itda.phase5-coding-plan-release-candidate.v2"] = (
        "itda.phase5-coding-plan-release-candidate.v2"
    )
    state: Literal["BUILT_UNACTIVATED"] = "BUILT_UNACTIVATED"
    analysis_origin: Literal["DEMO_MODEL_DERIVED"] = "DEMO_MODEL_DERIVED"
    model: Literal["glm-5v-turbo"] = "glm-5v-turbo"
    prompt_version: Literal["phase5-demo-profile.v1"] = "phase5-demo-profile.v1"
    provider_lane: Literal["CODING_PLAN_SUBSCRIPTION"] = "CODING_PLAN_SUBSCRIPTION"
    endpoint: Literal["https://api.z.ai/api/coding/paas/v4/chat/completions"] = (
        "https://api.z.ai/api/coding/paas/v4/chat/completions"
    )
    entitlement_evidence_sha256: Sha256 = CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256
    coding_plan_authority_sha256: Sha256 = CODING_PLAN_AUTHORITY_SHA256
    model_weight: Literal[1] = 1
    generation_sha256: Sha256
    generation_receipt_sha256: Sha256
    membership_sha256: Sha256
    hard_duplicate_adjudication_sha256: Sha256
    source_inventory_sha256: Sha256
    attempt_count: Annotated[int, Field(strict=True, ge=24, le=MAX_HTTP_ATTEMPTS)]
    subscription_total_weight: Annotated[int, Field(strict=True, ge=24, le=MAX_HTTP_ATTEMPTS)]
    retry_count: Annotated[int, Field(strict=True, ge=0, le=6)]
    profiles: Annotated[tuple[DemoModelDerivedProfile, ...], Field(min_length=24, max_length=24)]
    release_sha256: Sha256

    @model_validator(mode="after")
    def validate_release_candidate(self) -> Self:
        place_ids = tuple(profile.place_id for profile in self.profiles)
        if place_ids != tuple(sorted(place_ids)) or len(set(place_ids)) != 24:
            raise ValueError("release candidate requires exact canonical unique membership")
        if self.membership_sha256 != canonical_sha256(list(place_ids)):
            raise ValueError("release membership digest drifted")
        if self.hard_duplicate_adjudication_sha256 != HARD_DUPLICATE_ADJUDICATION_SHA256:
            raise ValueError("release hard-duplicate adjudication drifted")
        if (
            self.entitlement_evidence_sha256 != CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256
            or self.coding_plan_authority_sha256 != CODING_PLAN_AUTHORITY_SHA256
            or self.subscription_total_weight != self.attempt_count * self.model_weight
        ):
            raise ValueError("Coding Plan release authority or weight drifted")
        _require_self_digest(self, digest_field="release_sha256")
        return self


class Phase5NvidiaMinimaxReleaseCandidate(StrictContract):
    schema_version: Literal[
        "itda.phase5-nvidia-minimax-release-candidate.v4",
        "itda.phase5-nvidia-minimax-release-candidate.v5",
    ] = "itda.phase5-nvidia-minimax-release-candidate.v4"
    state: Literal["BUILT_UNACTIVATED"] = "BUILT_UNACTIVATED"
    analysis_origin: Literal["DEMO_MODEL_DERIVED"] = "DEMO_MODEL_DERIVED"
    model: Literal["minimaxai/minimax-m3"] = "minimaxai/minimax-m3"
    prompt_version: Literal[
        "phase5-demo-profile-sentinel-json.v4",
        "phase5-demo-profile-sentinel-json.v5",
    ] = "phase5-demo-profile-sentinel-json.v4"
    provider_lane: Literal["NVIDIA_NIM_API"] = "NVIDIA_NIM_API"
    endpoint: Literal["https://integrate.api.nvidia.com/v1/chat/completions"] = (
        "https://integrate.api.nvidia.com/v1/chat/completions"
    )
    authority_sha256: Sha256 = NVIDIA_AUTHORITY_SHA256
    generation_sha256: Sha256
    generation_receipt_sha256: Sha256
    membership_sha256: Sha256
    hard_duplicate_adjudication_sha256: Sha256
    source_inventory_sha256: Sha256
    config_sha256: Sha256
    resume_authority_sha256: Sha256 | None
    predecessor_manifest_sha256: Sha256 | None
    validated_membership_sha256: Sha256 | None
    remaining_membership_sha256: Sha256 | None
    attempt_count: Annotated[int, Field(strict=True, ge=24, le=MAX_HTTP_ATTEMPTS)]
    retry_count: Annotated[int, Field(strict=True, ge=0, le=6)]
    profiles: Annotated[
        tuple[NvidiaMinimaxModelDerivedProfile, ...], Field(min_length=24, max_length=24)
    ]
    release_sha256: Sha256

    @model_validator(mode="after")
    def validate_release_candidate(self) -> Self:
        expected_prompt_version = {
            "itda.phase5-nvidia-minimax-release-candidate.v4": (
                "phase5-demo-profile-sentinel-json.v4"
            ),
            "itda.phase5-nvidia-minimax-release-candidate.v5": (
                "phase5-demo-profile-sentinel-json.v5"
            ),
        }[self.schema_version]
        if self.prompt_version != expected_prompt_version:
            raise ValueError("NVIDIA release schema/prompt lineage drifted")
        expected_profile_schema = (
            "itda.nvidia-minimax-model-derived-profile.v5"
            if self.schema_version == "itda.phase5-nvidia-minimax-release-candidate.v5"
            else "itda.nvidia-minimax-model-derived-profile.v4"
        )
        if any(
            profile.schema_version != expected_profile_schema
            or profile.prompt_version != self.prompt_version
            or profile.model != self.model
            for profile in self.profiles
        ):
            raise ValueError("NVIDIA release nested profile lineage drifted")
        place_ids = tuple(profile.place_id for profile in self.profiles)
        if place_ids != tuple(sorted(place_ids)) or len(set(place_ids)) != 24:
            raise ValueError("release candidate requires exact canonical unique membership")
        if self.membership_sha256 != canonical_sha256(list(place_ids)):
            raise ValueError("release membership digest drifted")
        if self.hard_duplicate_adjudication_sha256 != HARD_DUPLICATE_ADJUDICATION_SHA256:
            raise ValueError("release hard-duplicate adjudication drifted")
        if self.authority_sha256 != NVIDIA_AUTHORITY_SHA256:
            raise ValueError("NVIDIA release authority drifted")
        if self.resume_authority_sha256 is None:
            if self.schema_version != "itda.phase5-nvidia-minimax-release-candidate.v4" or any(
                value is not None
                for value in (
                    self.predecessor_manifest_sha256,
                    self.validated_membership_sha256,
                    self.remaining_membership_sha256,
                )
            ):
                raise ValueError("fresh NVIDIA release contains resume lineage")
        elif self.resume_authority_sha256 == NVIDIA_RESUME_AUTHORITY_SHA256:
            raise ValueError("superseded NVIDIA resume authority cannot activate a release")
        elif self.resume_authority_sha256 == NVIDIA_SECOND_RESUME_AUTHORITY_SHA256 and (
            self.schema_version != "itda.phase5-nvidia-minimax-release-candidate.v4"
            or self.prompt_version != "phase5-demo-profile-sentinel-json.v4"
            or self.predecessor_manifest_sha256 != NVIDIA_SECOND_RESUME_RECONCILIATION_SHA256
            or self.validated_membership_sha256 != NVIDIA_SECOND_RESUME_VALIDATED_MEMBERSHIP_SHA256
            or self.remaining_membership_sha256 != NVIDIA_SECOND_RESUME_REMAINING_MEMBERSHIP_SHA256
        ):
            raise ValueError("second-resumed NVIDIA release authority drifted")
        elif self.resume_authority_sha256 == NVIDIA_V4_PROBE_RESUME_AUTHORITY_SHA256 and (
            self.schema_version != "itda.phase5-nvidia-minimax-release-candidate.v4"
            or self.prompt_version != "phase5-demo-profile-sentinel-json.v4"
            or self.predecessor_manifest_sha256
            != NVIDIA_V4_PROBE_RESUME_PREDECESSOR_MANIFEST_SHA256
            or self.validated_membership_sha256
            != NVIDIA_V4_PROBE_RESUME_VALIDATED_MEMBERSHIP_SHA256
            or self.remaining_membership_sha256
            != NVIDIA_V4_PROBE_RESUME_REMAINING_MEMBERSHIP_SHA256
        ):
            raise ValueError("v4 probe-resumed NVIDIA release authority drifted")
        elif self.resume_authority_sha256 == NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_SHA256:
            expected_predecessor = canonical_sha256(
                {
                    "attempt1": NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS[
                        "attempt1_root_manifest_sha256"
                    ],
                    "attempt2": NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS[
                        "attempt2_root_manifest_sha256"
                    ],
                }
            )
            if (
                self.schema_version != "itda.phase5-nvidia-minimax-release-candidate.v5"
                or self.predecessor_manifest_sha256 != expected_predecessor
                or self.validated_membership_sha256
                != NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS["validated_membership_sha256"]
                or self.remaining_membership_sha256
                != NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS["remaining_membership_sha256"]
                or (self.attempt_count, self.retry_count) != (26, 2)
            ):
                raise ValueError("v5 two-probe release authority drifted")
        elif self.resume_authority_sha256 in {
            NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_SHA256,
            NVIDIA_V5_ATTEMPT8_RESUME_AUTHORITY_SHA256,
        }:
            raise ValueError("stale retained-profile V5 authority cannot release")
        elif self.resume_authority_sha256 not in {
            NVIDIA_SECOND_RESUME_AUTHORITY_SHA256,
            NVIDIA_V4_PROBE_RESUME_AUTHORITY_SHA256,
            NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_SHA256,
        }:
            raise ValueError("resumed NVIDIA release authority drifted")
        _require_self_digest(self, digest_field="release_sha256")
        return self


class Phase5DemoReleaseReceipt(StrictContract):
    """Safe compare-and-swap activation receipt with no protected path."""

    schema_version: Literal["itda.phase5-demo-release-activation.v3"] = (
        "itda.phase5-demo-release-activation.v3"
    )
    state: Literal["ACTIVE"] = "ACTIVE"
    active_release_sha256: Sha256
    previous_release_sha256: Sha256 | None
    expected_current_sha256: Sha256 | None
    membership_sha256: Sha256
    hard_duplicate_adjudication_sha256: Sha256
    hard_duplicate_adjudication: HardDuplicateAdjudication
    analysis_origin: Literal["DEMO_MODEL_DERIVED"] = "DEMO_MODEL_DERIVED"
    member_count: Literal[24] = 24
    receipt_sha256: Sha256

    @model_validator(mode="after")
    def validate_activation_receipt(self) -> Self:
        if self.previous_release_sha256 != self.expected_current_sha256:
            raise ValueError("activation receipt does not preserve compare-and-swap input")
        if (
            self.hard_duplicate_adjudication_sha256
            != self.hard_duplicate_adjudication.adjudication_sha256
            or self.membership_sha256 != self.hard_duplicate_adjudication.dev_membership_sha256
        ):
            raise ValueError("activation receipt adjudication binding drifted")
        _require_self_digest(self, digest_field="receipt_sha256")
        return self


class PublicScoredReleaseSnapshot(StrictContract):
    """Public active-release projection consumed by recommendation code."""

    schema_version: Literal[
        "itda.public-scored-release-snapshot.v4",
        "itda.public-scored-release-snapshot.v5",
    ] = "itda.public-scored-release-snapshot.v4"
    state: Literal["ACTIVE"] = "ACTIVE"
    analysis_origin: Literal["DEMO_MODEL_DERIVED"] = "DEMO_MODEL_DERIVED"
    model: Literal["glm-5v-turbo", "minimaxai/minimax-m3"]
    prompt_version: Literal[
        "phase5-demo-profile.v1",
        "phase5-demo-profile-json.v2",
        "phase5-demo-profile-sentinel-json.v4",
        "phase5-demo-profile-sentinel-json.v5",
    ]
    release_sha256: Sha256
    membership_sha256: Sha256
    hard_duplicate_adjudication_sha256: Sha256
    hard_duplicate_adjudication: HardDuplicateAdjudication
    profiles: Annotated[tuple[PublicScoredProfile, ...], Field(min_length=24, max_length=24)]
    snapshot_sha256: Sha256

    @model_validator(mode="after")
    def validate_public_snapshot(self) -> Self:
        if (self.schema_version == "itda.public-scored-release-snapshot.v5") != (
            self.prompt_version == "phase5-demo-profile-sentinel-json.v5"
        ):
            raise ValueError("public snapshot schema/prompt lineage drifted")
        if any(
            profile.prompt_version != self.prompt_version or profile.model != self.model
            for profile in self.profiles
        ):
            raise ValueError("public snapshot nested profile lineage drifted")
        place_ids = tuple(profile.place_id for profile in self.profiles)
        if place_ids != tuple(sorted(place_ids)) or len(set(place_ids)) != 24:
            raise ValueError("public snapshot requires exact canonical unique membership")
        if self.membership_sha256 != canonical_sha256(list(place_ids)):
            raise ValueError("public snapshot membership digest drifted")
        adjudication = self.hard_duplicate_adjudication
        if (
            self.hard_duplicate_adjudication_sha256 != adjudication.adjudication_sha256
            or self.membership_sha256 != adjudication.dev_membership_sha256
            or {profile.place_id: profile.duplicate_group_id for profile in self.profiles}
            != adjudication.group_id_by_place
        ):
            raise ValueError("public snapshot hard-duplicate partition drifted")
        _require_self_digest(self, digest_field="snapshot_sha256")
        return self


__all__ = [
    "ATTEMPT_RESERVATION_MICRO_USD",
    "CODING_PLAN_AUTHORITY_SHA256",
    "CODING_PLAN_AUTHORITY_TEXT",
    "CODING_PLAN_BASE_URL",
    "CODING_PLAN_ENDPOINT",
    "CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256",
    "CODING_PLAN_MODEL_WEIGHT",
    "CodingPlanProfileAttempt",
    "CodingPlanProfileMaterializationConfig",
    "CodingPlanProfileMaterializationReceipt",
    "DemoModelDerivedProfile",
    "Phase5RecoveryProfileClassification",
    "DemoProfileAttempt",
    "DemoProfileMaterializationConfig",
    "DemoProfileMaterializationReceipt",
    "DemoProfileRequest",
    "DemoSourceBundle",
    "MAX_HTTP_ATTEMPTS",
    "MAX_PROVIDER_RESPONSE_BYTES",
    "MAX_RUN_COST_MICRO_USD",
    "NVIDIA_AUTHORITY_SHA256",
    "NVIDIA_AUTHORITY_TEXT",
    "NVIDIA_INITIAL_AUTHORITY_SHA256",
    "NVIDIA_INITIAL_AUTHORITY_TEXT",
    "NVIDIA_JSON_END_SENTINEL",
    "NVIDIA_JSON_START_SENTINEL",
    "NVIDIA_MAX_BOUNDED_JSON_BYTES",
    "NVIDIA_PROFILE_ENDPOINT",
    "NVIDIA_PROFILE_MODEL",
    "NVIDIA_PROVIDER_LANE",
    "NVIDIA_RESUME_PREDECESSOR_MANIFEST_SHA256",
    "NVIDIA_RESUME_AUTHORITY_SHA256",
    "NVIDIA_RESUME_AUTHORITY_TEXT",
    "NVIDIA_SECOND_RESUME_AUTHORITY_SHA256",
    "NVIDIA_SECOND_RESUME_AUTHORITY_TEXT",
    "NVIDIA_SECOND_RESUME_INTERRUPTED_PLACE_ID",
    "NVIDIA_SECOND_RESUME_RECONCILIATION_SHA256",
    "NVIDIA_SECOND_RESUME_REMAINING_MEMBERSHIP_SHA256",
    "NVIDIA_SECOND_RESUME_VALIDATED_MEMBERSHIP_SHA256",
    "NVIDIA_SUPERSEDED_RESUME_TERMINAL_SHA256",
    "NVIDIA_V4_PROBE_RESUME_ATTEMPT_SHA256",
    "NVIDIA_V4_PROBE_RESUME_AUTHORITY_SHA256",
    "NVIDIA_V4_PROBE_RESUME_AUTHORITY_TEXT",
    "NVIDIA_V4_PROBE_RESUME_FAILURE_SHA256",
    "NVIDIA_V4_PROBE_RESUME_PREDECESSOR_AUTHORITY_RECEIPT_SHA256",
    "NVIDIA_V4_PROBE_RESUME_PREDECESSOR_MANIFEST_SHA256",
    "NVIDIA_V4_PROBE_RESUME_REMAINING_MEMBERSHIP_SHA256",
    "NVIDIA_V4_PROBE_RESUME_REQUEST_SHA256",
    "NVIDIA_V4_PROBE_RESUME_RESPONSE_SHA256",
    "NVIDIA_V4_PROBE_RESUME_SOURCE_INVENTORY_SHA256",
    "NVIDIA_V4_PROBE_RESUME_TERMINAL_SHA256",
    "NVIDIA_V4_PROBE_RESUME_VALIDATED_MEMBERSHIP_SHA256",
    "NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_SHA256",
    "NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_TEXT",
    "NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS",
    "NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_SHA256",
    "NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_TEXT",
    "NVIDIA_V5_THREE_VALIDATED_RESUME_BINDINGS",
    "NVIDIA_V5_ATTEMPT8_RESUME_AUTHORITY_SHA256",
    "NVIDIA_V5_ATTEMPT8_RESUME_AUTHORITY_TEXT",
    "NVIDIA_V5_ATTEMPT8_RESUME_BINDINGS",
    "NVIDIA_TOOL_AUTHORITY_SHA256",
    "NVIDIA_TOOL_AUTHORITY_TEXT",
    "NvidiaMinimaxModelDerivedProfile",
    "NvidiaMinimaxProfileAttempt",
    "NvidiaMinimaxProfileMaterializationConfig",
    "NvidiaMinimaxProfileMaterializationReceipt",
    "NvidiaProviderTokenUsage",
    "PRICING_SNAPSHOT_SHA256",
    "PROFILE_ENDPOINT",
    "PROFILE_MODEL",
    "PricingSnapshot",
    "Phase5DemoReleaseCandidate",
    "Phase5CodingPlanReleaseCandidate",
    "Phase5NvidiaMinimaxReleaseCandidate",
    "Phase5RecoveryReleaseCandidate",
    "Phase5DemoRecoveryReleaseCandidate",
    "Phase5QuarantinedReleaseCandidate",
    "Phase5ReleaseLifecycle",
    "Phase5RecoveryActivePointer",
    "load_hard_duplicate_adjudication",
    "Phase5CandidateSmokeAttestation",
    "Phase5ActivationIntent",
    "Phase5PromotionReceipt",
    "Phase5InvalidationReceipt",
    "Phase5RollbackReceipt",
    "Phase5ActivationAttestation",
    "CandidateSmokeAttestation",
    "ActivationIntent",
    "PromotionReceipt",
    "InvalidationReceipt",
    "RollbackReceipt",
    "ActivationAttestation",
    "Phase5DemoReleaseReceipt",
    "PHASE5_RECOVERY_CANDIDATE_SCHEMA",
    "PHASE5_RELEASE_LIFECYCLE_SCHEMA",
    "PHASE5_CANDIDATE_SMOKE_SCHEMA",
    "PHASE5_ACTIVATION_INTENT_SCHEMA",
    "PHASE5_PROMOTION_SCHEMA",
    "PHASE5_INVALIDATION_SCHEMA",
    "PHASE5_ROLLBACK_SCHEMA",
    "PHASE5_ACTIVATION_ATTESTATION_SCHEMA",
    "ACTIVATION_SUITE_SHA256",
    "CONTRAST_SUITE_SHA256",
    "CANNOT_COAPPEAR_AUTHORITY_SHA256",
    "CANONICAL_SCENARIO_IDS",
    "CANONICAL_CONTRAST_PAIRS",
    "seal_demo_contract",
    "_require_digest",
    "_validate_recovery_maps",
    "_validate_child_digests",
    "Phase5DemoReleaseReceipt",
    "PublicScoredProfile",
    "PublicEvidenceExcerpt",
    "PublicScoredReleaseSnapshot",
    "ProviderTokenUsage",
    "ProviderUsageCharge",
    "QualifiedImageCapability",
    "seal_demo_contract",
]
