"""D-22 through D-26 optional-media policy and candidate projection contracts."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StrictContract
from itda.domain.canonical import canonical_sha256

POLICY_SCHEMA_VERSION = "itda.catalog-optional-media-policy.v2"
POLICY_VERSION = "optional-media-v2"
CANDIDATE_SCHEMA_VERSION = "itda.catalog-optional-media-candidate.v2"
OBSERVATION_SCHEMA_VERSION = "itda.photo-attributes.v1"
IMAGE_OBSERVATION_LABELS = (
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
NON_IMAGE_GATE_NAMES = (
    "canonical_identity",
    "coordinates",
    "description",
    "operating_information",
    "dataset_rights",
    "representation_assignment",
)
FORBIDDEN_MODEL_AUTHORITY_FIELDS = (
    "admission",
    "axis",
    "axis_score",
    "axis_scores",
    "catalog_eligible",
    "eligibility",
    "rank",
    "ranking",
    "recommendation_score",
    "selection",
)
HISTORICAL_PARENT_NAMES = (
    "aggregate_readiness_file_sha256",
    "aggregate_readiness_sha256",
    "decision_accounting_sha256",
    "entity_projection_file_sha256",
    "kto_collection_base",
    "kto_collection_success_root",
    "kto_eligibility_root",
    "kto_normalization_root",
    "kto_request_manifest_sha256",
    "kto_rights_attestation_sha256",
    "preflight_root_sha256",
    "reentry_disposition_root_sha256",
    "representation_quota_attestation_sha256",
    "substitution_root_sha256",
    "target_replay_sha256",
    "universe_replay_sha256",
)


class ImageMediumState(StrEnum):
    QUALIFIED = "QUALIFIED"
    MISSING = "MISSING"
    EMPTY = "EMPTY"
    PROVENANCE_INCOMPLETE = "PROVENANCE_INCOMPLETE"
    RIGHTS_RESTRICTED = "RIGHTS_RESTRICTED"
    ANALYSIS_FAILED = "ANALYSIS_FAILED"


class GateState(StrEnum):
    PASS = "PASS"
    MISSING = "MISSING"
    BLOCKED = "BLOCKED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


class RightsLaneState(StrEnum):
    PASS = "PASS"
    MISSING = "MISSING"
    BLOCKED = "BLOCKED"


class NonImageEligibilityGates(StrictContract):
    canonical_identity: GateState
    coordinates: GateState
    description: GateState
    operating_information: GateState
    dataset_rights: GateState
    representation_assignment: GateState

    @property
    def eligible(self) -> bool:
        return all(getattr(self, name) is GateState.PASS for name in NON_IMAGE_GATE_NAMES)

    @property
    def failure_reasons(self) -> tuple[str, ...]:
        return tuple(
            name for name in NON_IMAGE_GATE_NAMES if getattr(self, name) is not GateState.PASS
        )


class ImageMediumEligibility(StrictContract):
    state: ImageMediumState
    reason_code: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    dataset_rights_state: RightsLaneState
    image_asset_rights_state: RightsLaneState
    provenance_complete: Annotated[bool, Field(strict=True)]
    analysis_eligible: Annotated[bool, Field(strict=True)]
    ui_eligible: Annotated[bool, Field(strict=True)]
    demo_eligible: Annotated[bool, Field(strict=True)]
    image_observation_eligible: Annotated[bool, Field(strict=True)]
    evidence_refs: tuple[Sha256, ...]

    @model_validator(mode="after")
    def validate_lanes(self) -> Self:
        qualified = self.state is ImageMediumState.QUALIFIED
        lanes = (
            self.analysis_eligible,
            self.ui_eligible,
            self.demo_eligible,
            self.image_observation_eligible,
        )
        if qualified and (
            self.dataset_rights_state is not RightsLaneState.PASS
            or self.image_asset_rights_state is not RightsLaneState.PASS
            or not self.provenance_complete
            or not all(lanes)
        ):
            raise ValueError("qualified image requires separate passing rights and lanes")
        if not qualified and any(lanes):
            raise ValueError("unqualified image cannot authorize a downstream lane")
        if not self.evidence_refs or len(set(self.evidence_refs)) != len(self.evidence_refs):
            raise ValueError("image medium requires unique exact evidence")
        return self


class FusionPolicy(StrictContract):
    downstream_phase: Literal["phase-4"]
    base_media_lanes: tuple[Literal["description", "odii", "image"], ...]
    renormalization_required_without_qualified_image: Literal[True]
    scoring_performed_in_phase_2: Literal[False]
    ranking_performed_in_phase_2: Literal[False]

    @model_validator(mode="after")
    def validate_lane_order(self) -> Self:
        if self.base_media_lanes != ("description", "odii", "image"):
            raise ValueError("fusion lanes must retain the frozen description/Odii/image order")
        return self


class ModelBoundary(StrictContract):
    model_id: Literal["glm-5v-turbo"]
    role: Literal["offline-candidate-metadata-only"]
    observation_schema_version: Literal["itda.photo-attributes.v1"]
    observation_schema_sha256: Sha256
    live_spike_status: Literal["PARTIAL"]
    production_user_photo_status: Literal["BLOCKED"]
    model_may_select_or_rank: Literal[False]
    model_may_admit_catalog_place: Literal[False]
    local_schema_validation_required: Literal[True]
    forbidden_authority_fields: tuple[str, ...]

    @model_validator(mode="after")
    def validate_boundary(self) -> Self:
        if self.forbidden_authority_fields != FORBIDDEN_MODEL_AUTHORITY_FIELDS:
            raise ValueError("model authority-field denylist drifted")
        if self.observation_schema_sha256 != observation_schema_sha256():
            raise ValueError("shared observation schema hash drifted")
        return self


class OptionalMediaPolicyV2(StrictContract):
    schema_version: Literal["itda.catalog-optional-media-policy.v2"]
    policy_version: Literal["optional-media-v2"]
    non_image_gate_names: tuple[str, ...]
    image_medium_states: tuple[str, ...]
    image_observation_labels: tuple[str, ...]
    image_failures_are_place_failures: Literal[False]
    dataset_and_asset_rights_are_separate: Literal[True]
    model_boundary: ModelBoundary
    fusion_policy: FusionPolicy
    policy_sha256: Sha256

    @classmethod
    def from_manifest(cls, payload: Mapping[str, object]) -> OptionalMediaPolicyV2:
        return cls.model_validate(payload)

    @model_validator(mode="after")
    def validate_policy(self) -> Self:
        if self.non_image_gate_names != NON_IMAGE_GATE_NAMES:
            raise ValueError("non-image gate inventory drifted")
        if self.image_medium_states != tuple(state.value for state in ImageMediumState):
            raise ValueError("image medium state inventory drifted")
        if self.image_observation_labels != IMAGE_OBSERVATION_LABELS:
            raise ValueError("image observation label inventory drifted")
        expected = canonical_sha256(self.model_dump(exclude={"policy_sha256"}, mode="json"))
        if self.policy_sha256 != expected:
            raise ValueError("optional-media policy hash does not match")
        return self


class ObservationValue(StrictContract):
    status: Literal["observed", "not_observable"]
    score: Annotated[float | None, Field(strict=True, ge=0.0, le=4.0)] = None
    evidence: tuple[Annotated[str, Field(strict=True, min_length=1, max_length=500)], ...] = Field(
        default=(), max_length=3
    )

    @model_validator(mode="after")
    def validate_observation(self) -> Self:
        if self.status == "observed" and (self.score is None or not self.evidence):
            raise ValueError("observed image attribute requires score and visible evidence")
        if self.status == "not_observable" and (self.score is not None or self.evidence):
            raise ValueError("not-observable image attribute cannot carry evidence or score")
        return self


class VlmObservationEnvelope(StrictContract):
    schema_version: Literal["itda.photo-attributes.v1"]
    observations: dict[str, ObservationValue]

    @model_validator(mode="after")
    def validate_inventory(self) -> Self:
        if tuple(self.observations) != IMAGE_OBSERVATION_LABELS:
            raise ValueError("observations must contain ordered H1-H4, I1-I4, and R1-R4")
        return self


class OptionalMediaCandidate(StrictContract):
    schema_version: Literal["itda.catalog-optional-media-candidate.v2"]
    policy_version: Literal["optional-media-v2"]
    policy_sha256: Sha256
    place_entity_id: Annotated[str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")]
    provider_place_candidate_id: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=200)
    ] = None
    representation_primary_group: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=80)
    ] = None
    source_row_sha256: Sha256
    historical_row_sha256: Sha256
    non_image_gates: NonImageEligibilityGates
    catalog_eligible: Annotated[bool, Field(strict=True)]
    non_image_failure_reasons: tuple[str, ...]
    image_medium: ImageMediumEligibility
    renormalization_required: Annotated[bool, Field(strict=True)]
    model_selection_authority: Literal[False]
    row_sha256: Sha256

    @model_validator(mode="after")
    def validate_candidate(self) -> Self:
        if self.catalog_eligible != self.non_image_gates.eligible:
            raise ValueError("catalog eligibility must derive only from non-image gates")
        if self.non_image_failure_reasons != self.non_image_gates.failure_reasons:
            raise ValueError("non-image failure reasons do not match gate states")
        expected_renormalization = self.image_medium.state is not ImageMediumState.QUALIFIED
        if self.renormalization_required != expected_renormalization:
            raise ValueError("image-lane renormalization obligation does not match state")
        expected = canonical_sha256(self.model_dump(exclude={"row_sha256"}, mode="json"))
        if self.row_sha256 != expected:
            raise ValueError("optional-media candidate hash does not match")
        return self


class HistoricalLineageBinding(StrictContract):
    terminal_history_sha256: Sha256
    terminal_artifact_file_sha256: Sha256
    terminal_root_sha256: Sha256
    cited_roots: dict[str, Sha256]

    @model_validator(mode="after")
    def validate_lineage(self) -> Self:
        if tuple(sorted(self.cited_roots)) != tuple(sorted(HISTORICAL_PARENT_NAMES)):
            raise ValueError("historical lineage binding has a mixed parent inventory")
        return self


class ReplayCapabilities(StrictContract):
    provider_traffic_allowed: Literal[False]
    credential_access_allowed: Literal[False]
    vlm_inference_allowed: Literal[False]
    catalog_membership_authority: Literal[False]
    split_membership_authority: Literal[False]
    schema_mutation_authority: Literal[False]
    rights_waiver_authority: Literal[False]


class OptionalMediaCandidateSet(StrictContract):
    schema_version: Literal["itda.catalog-optional-media-candidates.v2"]
    policy_version: Literal["optional-media-v2"]
    policy_sha256: Sha256
    candidates: tuple[OptionalMediaCandidate, ...]
    universe_count: Annotated[int, Field(strict=True, ge=1, le=1_000)]
    catalog_eligible_count: Annotated[int, Field(strict=True, ge=0, le=1_000)]
    image_state_counts: dict[str, Annotated[int, Field(strict=True, ge=0, le=1_000)]]
    candidates_root_sha256: Sha256
    candidate_set_sha256: Sha256

    @model_validator(mode="after")
    def validate_candidate_set(self) -> Self:
        ids = tuple(row.place_entity_id for row in self.candidates)
        if ids != tuple(sorted(ids)) or len(set(ids)) != len(ids):
            raise ValueError("optional-media candidates require unique canonical ID order")
        if self.universe_count != len(self.candidates):
            raise ValueError("optional-media universe count is not candidate-derived")
        if self.catalog_eligible_count != sum(row.catalog_eligible for row in self.candidates):
            raise ValueError("optional-media eligible count is not candidate-derived")
        expected_states = {
            state.value: sum(row.image_medium.state is state for row in self.candidates)
            for state in ImageMediumState
        }
        if self.image_state_counts != expected_states:
            raise ValueError("optional-media image counts are not candidate-derived")
        expected_root = canonical_sha256([row.model_dump(mode="json") for row in self.candidates])
        if self.candidates_root_sha256 != expected_root:
            raise ValueError("optional-media candidate root does not match")
        expected = canonical_sha256(self.model_dump(exclude={"candidate_set_sha256"}, mode="json"))
        if self.candidate_set_sha256 != expected:
            raise ValueError("optional-media candidate-set hash does not match")
        return self


class OptionalMediaProjection(StrictContract):
    schema_version: Literal["itda.catalog-optional-media-projection.v2"]
    policy: OptionalMediaPolicyV2
    candidate_set: OptionalMediaCandidateSet
    historical_lineage: HistoricalLineageBinding
    source_files: dict[str, Sha256]
    capabilities: ReplayCapabilities
    provider_attempts: tuple[()] = ()
    projection_sha256: Sha256

    @property
    def candidates(self) -> tuple[OptionalMediaCandidate, ...]:
        return self.candidate_set.candidates

    @property
    def universe_count(self) -> int:
        return self.candidate_set.universe_count

    @property
    def catalog_eligible_count(self) -> int:
        return self.candidate_set.catalog_eligible_count

    @property
    def image_state_counts(self) -> dict[str, int]:
        return self.candidate_set.image_state_counts

    @model_validator(mode="after")
    def validate_projection(self) -> Self:
        if (
            self.candidate_set.policy_sha256 != self.policy.policy_sha256
            or self.candidate_set.policy_version != self.policy.policy_version
        ):
            raise ValueError("optional-media projection mixes policy versions")
        if not self.source_files or tuple(self.source_files) != tuple(sorted(self.source_files)):
            raise ValueError("optional-media source file hashes require canonical order")
        expected = canonical_sha256(self.model_dump(exclude={"projection_sha256"}, mode="json"))
        if self.projection_sha256 != expected:
            raise ValueError("optional-media projection hash does not match")
        return self


def observation_schema_sha256() -> str:
    definition = {
        "schema_version": OBSERVATION_SCHEMA_VERSION,
        "labels": IMAGE_OBSERVATION_LABELS,
        "observation": {
            "status": ("observed", "not_observable"),
            "score": {"type": "number-or-null", "minimum": 0.0, "maximum": 4.0},
            "evidence": {"type": "ordered-string-list", "maximum_items": 3},
        },
        "authority_fields_forbidden": FORBIDDEN_MODEL_AUTHORITY_FIELDS,
        "axis_derivation": "deterministic-local-only",
    }
    return canonical_sha256(definition)


def build_optional_media_policy() -> OptionalMediaPolicyV2:
    fields: dict[str, Any] = {
        "schema_version": POLICY_SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "non_image_gate_names": NON_IMAGE_GATE_NAMES,
        "image_medium_states": tuple(state.value for state in ImageMediumState),
        "image_observation_labels": IMAGE_OBSERVATION_LABELS,
        "image_failures_are_place_failures": False,
        "dataset_and_asset_rights_are_separate": True,
        "model_boundary": {
            "model_id": "glm-5v-turbo",
            "role": "offline-candidate-metadata-only",
            "observation_schema_version": OBSERVATION_SCHEMA_VERSION,
            "observation_schema_sha256": observation_schema_sha256(),
            "live_spike_status": "PARTIAL",
            "production_user_photo_status": "BLOCKED",
            "model_may_select_or_rank": False,
            "model_may_admit_catalog_place": False,
            "local_schema_validation_required": True,
            "forbidden_authority_fields": FORBIDDEN_MODEL_AUTHORITY_FIELDS,
        },
        "fusion_policy": {
            "downstream_phase": "phase-4",
            "base_media_lanes": ("description", "odii", "image"),
            "renormalization_required_without_qualified_image": True,
            "scoring_performed_in_phase_2": False,
            "ranking_performed_in_phase_2": False,
        },
    }
    return OptionalMediaPolicyV2(
        **fields,
        policy_sha256=canonical_sha256(fields),
    )


def _mapping(value: object, *, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be an object")
    return value


def _gate(value: object) -> GateState:
    if value == "PASS":
        return GateState.PASS
    if value == "MISSING":
        return GateState.MISSING
    if value in {"REVIEW_REQUIRED", "AMBIGUOUS"}:
        return GateState.REVIEW_REQUIRED
    return GateState.BLOCKED


def _rights_state(value: object) -> RightsLaneState:
    if value == "PASS":
        return RightsLaneState.PASS
    if value == "MISSING":
        return RightsLaneState.MISSING
    return RightsLaneState.BLOCKED


def _image_state(
    historical_row: Mapping[str, object],
    asset_rights: Mapping[str, object],
) -> ImageMediumState:
    explicit = historical_row.get("image_medium_state")
    if explicit is not None:
        if not isinstance(explicit, str):
            raise ValueError("unknown image medium state")
        try:
            return ImageMediumState(explicit)
        except ValueError as exc:
            raise ValueError("unknown image medium state") from exc
    direct = historical_row.get("direct_media_state")
    reason = str(asset_rights.get("reason", ""))
    if direct == "PASS":
        return ImageMediumState.QUALIFIED
    if direct == "MISSING":
        return ImageMediumState.EMPTY if "SUCCESS_EMPTY" in reason else ImageMediumState.MISSING
    if direct == "ANALYSIS_FAILED":
        return ImageMediumState.ANALYSIS_FAILED
    if "PROVENANCE" in reason:
        return ImageMediumState.PROVENANCE_INCOMPLETE
    return ImageMediumState.RIGHTS_RESTRICTED


def project_optional_media_candidate(
    source_row: Mapping[str, object],
    historical_row: Mapping[str, object],
    policy: OptionalMediaPolicyV2,
) -> OptionalMediaCandidate:
    """Project one candidate without allowing image state to affect place eligibility."""

    policy = OptionalMediaPolicyV2.from_manifest(policy.model_dump(mode="json"))
    source_gates = _mapping(
        source_row.get("objective_gate_states"),
        field="source objective gate states",
    )
    dataset_rights = _mapping(
        historical_row.get("dataset_rights", {"state": source_gates.get("dataset_rights")}),
        field="dataset rights",
    )
    asset_rights = _mapping(
        historical_row.get("asset_rights"),
        field="image asset rights",
    )
    non_image = NonImageEligibilityGates(
        canonical_identity=_gate(historical_row.get("identity_state")),
        coordinates=_gate(historical_row.get("coordinates_state", source_gates.get("coordinates"))),
        description=_gate(historical_row.get("description_state", source_gates.get("description"))),
        operating_information=_gate(
            historical_row.get(
                "operating_info_state",
                source_gates.get("operating_info"),
            )
        ),
        dataset_rights=_gate(dataset_rights.get("state")),
        representation_assignment=_gate(
            "PASS"
            if source_row.get("representation_assignment_status") == "PRIMARY"
            else source_row.get("representation_assignment_status")
        ),
    )
    image_state = _image_state(historical_row, asset_rights)
    evidence_refs = tuple(
        sorted(
            {
                value
                for value in (
                    dataset_rights.get("attestation_sha256"),
                    asset_rights.get("attestation_sha256"),
                    historical_row.get("response_evidence_sha256"),
                    source_row.get("row_sha256"),
                )
                if isinstance(value, str)
                and len(value) == 64
                and all(character in "0123456789abcdef" for character in value)
            }
        )
    )
    qualified = image_state is ImageMediumState.QUALIFIED
    image_medium = ImageMediumEligibility(
        state=image_state,
        reason_code=str(asset_rights.get("reason", image_state.value)),
        dataset_rights_state=_rights_state(dataset_rights.get("state")),
        image_asset_rights_state=_rights_state(asset_rights.get("state")),
        provenance_complete=bool(asset_rights.get("provenance_complete", qualified)),
        analysis_eligible=bool(asset_rights.get("analysis_eligible", False)),
        ui_eligible=bool(asset_rights.get("ui_eligible", False)),
        demo_eligible=bool(asset_rights.get("demo_eligible", False)),
        image_observation_eligible=qualified,
        evidence_refs=evidence_refs,
    )
    fields: dict[str, Any] = {
        "schema_version": CANDIDATE_SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "policy_sha256": policy.policy_sha256,
        "place_entity_id": source_row.get("place_entity_id"),
        "provider_place_candidate_id": source_row.get("provider_place_candidate_id"),
        "representation_primary_group": source_row.get("representation_primary_group"),
        "source_row_sha256": source_row.get("row_sha256"),
        "historical_row_sha256": canonical_sha256(historical_row),
        "non_image_gates": non_image,
        "catalog_eligible": non_image.eligible,
        "non_image_failure_reasons": non_image.failure_reasons,
        "image_medium": image_medium,
        "renormalization_required": not qualified,
        "model_selection_authority": False,
    }
    return OptionalMediaCandidate(
        **fields,
        row_sha256=canonical_sha256(
            {
                **fields,
                "non_image_gates": non_image.model_dump(mode="json"),
                "image_medium": image_medium.model_dump(mode="json"),
            }
        ),
    )


def verify_historical_lineage(
    failure_payload: Mapping[str, object],
    expected_sha256: str,
) -> None:
    """Verify the immutable Plan 49 terminal envelope and every cited digest shape."""

    payload = _mapping(failure_payload.get("payload"), field="terminal failure payload")
    recorded_root = failure_payload.get("terminal_root_sha256")
    if (
        not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or recorded_root != expected_sha256
        or canonical_sha256(payload) != expected_sha256
    ):
        raise ValueError("historical lineage root differs from the pinned Plan 49 digest")
    parents = _mapping(payload.get("parents"), field="terminal failure parents")
    if tuple(sorted(parents)) != tuple(sorted(HISTORICAL_PARENT_NAMES)):
        raise ValueError("historical lineage parent inventory drifted")
    if any(
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
        for value in parents.values()
    ):
        raise ValueError("historical lineage contains an invalid parent digest")
    capabilities = _mapping(payload.get("capabilities"), field="terminal capabilities")
    external_effects = _mapping(
        payload.get("external_effects"),
        field="terminal external effects",
    )
    if (
        payload.get("schema_version") != "itda.kto-recovery-terminal-failure.v1"
        or payload.get("status") != "REENTRY_EXHAUSTED"
        or payload.get("terminal") is not True
        or payload.get("summary_permitted") is not False
        or payload.get("unresolved_count") != 15
        or payload.get("substitute_count") != 0
        or payload.get("reentry_ordinal") != 0
        or payload.get("plan50_reachable") is not False
        or any(value is not False for value in capabilities.values())
        or any(value is not False for value in external_effects.values())
    ):
        raise ValueError("historical Plan 49 terminal semantics drifted")


__all__ = [
    "CANDIDATE_SCHEMA_VERSION",
    "FORBIDDEN_MODEL_AUTHORITY_FIELDS",
    "GateState",
    "HISTORICAL_PARENT_NAMES",
    "HistoricalLineageBinding",
    "IMAGE_OBSERVATION_LABELS",
    "ImageMediumEligibility",
    "ImageMediumState",
    "ModelBoundary",
    "NON_IMAGE_GATE_NAMES",
    "NonImageEligibilityGates",
    "OBSERVATION_SCHEMA_VERSION",
    "ObservationValue",
    "OptionalMediaCandidate",
    "OptionalMediaCandidateSet",
    "OptionalMediaPolicyV2",
    "OptionalMediaProjection",
    "POLICY_SCHEMA_VERSION",
    "POLICY_VERSION",
    "RightsLaneState",
    "ReplayCapabilities",
    "VlmObservationEnvelope",
    "build_optional_media_policy",
    "observation_schema_sha256",
    "project_optional_media_candidate",
    "verify_historical_lineage",
]
