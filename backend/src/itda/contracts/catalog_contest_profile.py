"""Strict contracts for the noncommercial contest-use catalog successor."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import Field, field_validator, model_validator

from itda.contracts.base import Sha256, StrictContract
from itda.contracts.catalog_readiness import GROUP_ORDER, RepresentationGroup
from itda.domain.canonical import canonical_sha256

CONTEST_SCOPE = "noncommercial_contest_demo_evaluation"
POLICY_SCHEMA_VERSION = "itda.catalog-contest-use-official-public-data-profile.v1"
SOURCE_GRANTS_SCHEMA_VERSION = "itda.catalog-contest-use-source-grants.v1"
ACCOUNTING_SCHEMA_VERSION = "itda.catalog-contest-use-candidate-accounting.v1"
FRONTIER_SCHEMA_VERSION = "itda.catalog-contest-use-selection-frontier.v1"
REPLAY_SCHEMA_VERSION = "itda.catalog-contest-use-replay-attestation.v1"
HANDOFF_SCHEMA_VERSION = "itda.catalog-contest-use-plan54-handoff.v1"
TERMINAL_SCHEMA_VERSION = "itda.catalog-contest-use-terminal.v1"
MANIFEST_SCHEMA_VERSION = "itda.catalog-contest-use-generation-manifest.v1"
RECEIPT_SCHEMA_VERSION = "itda.catalog-contest-use-generation-receipt.v1"


def _canonical_line_sha256(payload: object) -> str:
    """Digest the exact single-line canonical JSON emitted by jq -c."""

    from itda.domain.canonical import canonical_json_bytes  # noqa: PLC0415

    return hashlib.sha256(canonical_json_bytes(payload) + b"\n").hexdigest()


class ContestUseScope(StrEnum):
    NONCOMMERCIAL_CONTEST_DEMO_EVALUATION = CONTEST_SCOPE


class DatasetPermissionDisposition(StrEnum):
    DATASET_UNRESTRICTED_QUALIFIED = "DATASET_UNRESTRICTED_QUALIFIED"
    EXPLICIT_NARROWER_EXCLUDED = "EXPLICIT_NARROWER_EXCLUDED"
    UNIDENTIFIED_THIRD_PARTY_EXCLUDED = "UNIDENTIFIED_THIRD_PARTY_EXCLUDED"
    DATASET_GRANT_UNRESOLVED = "DATASET_GRANT_UNRESOLVED"


class EvidenceAvailability(StrEnum):
    QUALIFIED = "QUALIFIED"
    MISSING = "MISSING"
    EXCLUDED = "EXCLUDED"


class ContestProfileTerminalCode(StrEnum):
    FORBIDDEN_CAPABILITY_REQUESTED = "FORBIDDEN_CAPABILITY_REQUESTED"
    HISTORICAL_LINEAGE_DRIFT = "HISTORICAL_LINEAGE_DRIFT"
    NONCANONICAL_HELD_INPUT = "NONCANONICAL_HELD_INPUT"
    INCOMPLETE_UNIVERSE = "INCOMPLETE_UNIVERSE"
    RIGHTS_OR_SOURCE_AMBIGUITY = "RIGHTS_OR_SOURCE_AMBIGUITY"
    HUMAN_DECISION_LIMIT_EXCEEDED = "HUMAN_DECISION_LIMIT_EXCEEDED"
    REPRESENTATION_QUOTA_INFEASIBLE = "REPRESENTATION_QUOTA_INFEASIBLE"
    SELECTABLE_COUNT_SHORTFALL = "SELECTABLE_COUNT_SHORTFALL"
    REPLAY_MISMATCH = "REPLAY_MISMATCH"


QualifiedChannel = Literal["official_description", "odii", "metadata", "image"]


class AxisEvidenceBasis(StrictContract):
    """Qualified evidence lanes without synthesized observations."""

    image_availability: EvidenceAvailability
    operating_information_availability: EvidenceAvailability
    qualified_channels: tuple[QualifiedChannel, ...]
    availability_warnings: tuple[str, ...]
    known_operating_facts: dict[str, str]
    inferred_image_facts: tuple[()] = ()
    inferred_operating_facts: tuple[()] = ()
    axis_contract_version: Literal["contest-three-axis-evidence-v1"] = (
        "contest-three-axis-evidence-v1"
    )
    vlm_invoked: Literal[False] = False

    @model_validator(mode="after")
    def validate_basis(self) -> Self:
        expected = ("official_description", "odii", "metadata") + (
            ("image",) if self.image_availability is EvidenceAvailability.QUALIFIED else ()
        )
        if self.qualified_channels != expected:
            raise ValueError("axis evidence channels drifted from availability")
        expected_warnings = tuple(
            warning
            for warning, active in (
                (
                    "IMAGE_EVIDENCE_UNAVAILABLE",
                    self.image_availability is not EvidenceAvailability.QUALIFIED,
                ),
                (
                    "OPERATING_INFORMATION_UNAVAILABLE",
                    self.operating_information_availability is not EvidenceAvailability.QUALIFIED,
                ),
            )
            if active
        )
        if self.availability_warnings != expected_warnings:
            raise ValueError("availability warnings drifted from evidence state")
        return self


class ContestProfileConfidence(StrictContract):
    """Disclosure/qualification signal that has no selection authority."""

    band: Literal["QUALIFIED", "REDUCED", "GATED"]
    qualification_eligible: Annotated[bool, Field(strict=True)]
    warning_codes: tuple[str, ...]
    qualification_filter_only: Literal[True] = True
    selection_score_contribution: Literal[0] = 0
    affects_representation_group: Literal[False] = False
    affects_quota: Literal[False] = False
    affects_ordering: Literal[False] = False
    popularity_bonus: Literal[0] = 0

    @model_validator(mode="after")
    def validate_confidence(self) -> Self:
        if self.band == "QUALIFIED" and self.warning_codes:
            raise ValueError("qualified confidence cannot hide availability warnings")
        if self.band == "GATED" and self.qualification_eligible:
            raise ValueError("gated confidence cannot claim qualification")
        return self


class ContestUsePolicy(StrictContract):
    schema_version: Literal["itda.catalog-contest-use-official-public-data-profile.v1"] = (
        "itda.catalog-contest-use-official-public-data-profile.v1"
    )
    policy_version: Literal["contest-use-official-public-data-v1"] = (
        "contest-use-official-public-data-v1"
    )
    scope: ContestUseScope = ContestUseScope.NONCOMMERCIAL_CONTEST_DEMO_EVALUATION
    commercial_production_rights_review_required: Literal[True] = True
    official_dataset_grants_root_sha256: Sha256
    asset_exclusions_root_sha256: Sha256
    contest_rights_root_sha256: Sha256
    source_neutral_entities_root_sha256: Sha256
    relationship_leaves_root_sha256: Sha256
    representation_rule_sha256: Sha256
    missingness_state_root_sha256: Sha256
    warning_state_root_sha256: Sha256
    confidence_state_root_sha256: Sha256
    commercial_review_requirement_sha256: Sha256
    immutable_parents_root_sha256: Sha256
    complete_universe_root_sha256: Sha256
    confidence_is_qualification_filter_only: Literal[True] = True
    confidence_adds_score: Literal[False] = False
    image_presence_adds_score: Literal[False] = False
    popularity_adds_score: Literal[False] = False
    policy_sha256: Sha256

    @model_validator(mode="after")
    def validate_policy(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"policy_sha256"}, mode="json"))
        if self.policy_sha256 != expected:
            raise ValueError("contest policy digest drifted")
        return self


class ContestCandidateAccounting(StrictContract):
    schema_version: Literal["itda.catalog-contest-use-candidate-accounting.v1"] = (
        "itda.catalog-contest-use-candidate-accounting.v1"
    )
    place_entity_id: Annotated[str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")]
    source_candidate_id: Annotated[
        str | None,
        Field(strict=True, pattern=r"^candidate:(tour-api|odii|tourism-photo):[A-Za-z0-9._:-]+$"),
    ]
    source_row_sha256: Sha256
    representation_primary_group: RepresentationGroup | None
    objective_eligible: Annotated[bool, Field(strict=True)]
    blocking_deficits: tuple[str, ...]
    image_availability: EvidenceAvailability
    operating_information_availability: EvidenceAvailability
    axis_evidence_basis: AxisEvidenceBasis
    confidence: ContestProfileConfidence
    dataset_permission: DatasetPermissionDisposition
    dataset_grant_sha256: Sha256
    asset_exclusion_root_sha256: Sha256
    row_sha256: Sha256

    @field_validator("blocking_deficits")
    @classmethod
    def canonical_deficits(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("contest blocking deficits must be canonical and unique")
        if "operating_information" in value or "image" in value:
            raise ValueError(
                "missing operating information or image cannot block contest eligibility"
            )
        return value

    @model_validator(mode="after")
    def validate_row(self) -> Self:
        if self.objective_eligible:
            if (
                self.blocking_deficits
                or self.representation_primary_group is None
                or self.source_candidate_id is None
            ):
                raise ValueError("eligible contest row must be assigned and deficit-free")
            if (
                self.dataset_permission
                is not DatasetPermissionDisposition.DATASET_UNRESTRICTED_QUALIFIED
            ):
                raise ValueError(
                    "eligible contest row requires a qualified official dataset record"
                )
        elif not self.blocking_deficits:
            raise ValueError("ineligible contest row requires a named objective deficit")
        expected = canonical_sha256(self.model_dump(exclude={"row_sha256"}, mode="json"))
        if self.row_sha256 != expected:
            raise ValueError("contest accounting row digest drifted")
        return self


class ContestSelectionFrontier(StrictContract):
    schema_version: Literal["itda.catalog-contest-use-selection-frontier.v1"] = (
        "itda.catalog-contest-use-selection-frontier.v1"
    )
    scope: ContestUseScope = ContestUseScope.NONCOMMERCIAL_CONTEST_DEMO_EVALUATION
    universe_count: Literal[718]
    candidate_accounting_root_sha256: Sha256
    eligible_pool: tuple[dict[str, Any], ...]
    eligible_pool_sha256: Sha256
    eligible_candidate_count: Literal[40]
    eligible_group_counts: dict[RepresentationGroup, int]
    capped_capacity: Literal[38]
    quota_config_sha256: Sha256
    quota_proof_sha256: Sha256
    final_quotas: dict[RepresentationGroup, int]
    noncanonical_preview_ids: tuple[str, ...]
    exact_36_sha256: Sha256
    selectable_candidate_count: Literal[36]
    preview_is_canonical_catalog: Literal[False] = False
    human_choice_and_order_required: Literal[True] = True
    confidence_used_for_selection: Literal[False] = False
    popularity_used_for_selection: Literal[False] = False
    ordering_rule: Literal["group-ordinal-then-canonical-utf8-source-neutral-id"] = (
        "group-ordinal-then-canonical-utf8-source-neutral-id"
    )
    human_decision_count: Annotated[int, Field(strict=True, ge=0, le=6)]
    frontier_sha256: Sha256

    @model_validator(mode="after")
    def validate_frontier(self) -> Self:
        if set(self.eligible_group_counts) != set(GROUP_ORDER):
            raise ValueError("contest eligible group keys drifted")
        if set(self.final_quotas) != set(GROUP_ORDER):
            raise ValueError("contest quota keys drifted")
        if self.eligible_group_counts != {
            "history_culture": 13,
            "history_scenery_boundary": 6,
            "image_modern_content": 8,
            "rest_walk_immersion": 13,
        }:
            raise ValueError("contest eligible group counts drifted")
        if self.final_quotas != {
            "history_culture": 12,
            "history_scenery_boundary": 6,
            "image_modern_content": 7,
            "rest_walk_immersion": 11,
        }:
            raise ValueError("contest quotas drifted")
        if len(self.eligible_pool) != 40 or self.eligible_pool_sha256 != canonical_sha256(
            list(self.eligible_pool)
        ):
            raise ValueError("contest eligible pool drifted")
        if (
            len(self.noncanonical_preview_ids) != 36
            or len(set(self.noncanonical_preview_ids)) != 36
            or self.exact_36_sha256 != canonical_sha256(list(self.noncanonical_preview_ids))
        ):
            raise ValueError("contest non-canonical exact-36 proof drifted")
        expected = canonical_sha256(self.model_dump(exclude={"frontier_sha256"}, mode="json"))
        if self.frontier_sha256 != expected:
            raise ValueError("contest selection frontier digest drifted")
        return self


class ContestReplayAttestation(StrictContract):
    schema_version: Literal["itda.catalog-contest-use-replay-attestation.v1"] = (
        "itda.catalog-contest-use-replay-attestation.v1"
    )
    replay_ordinal: Literal[1, 2]
    boundary_hashes: dict[str, Any]
    immutable_parents_root_sha256: Sha256
    policy_sha256: Sha256
    candidate_accounting_root_sha256: Sha256
    frontier_sha256: Sha256
    eligible_pool_sha256: Sha256
    exact_36_sha256: Sha256
    quota_proof_sha256: Sha256
    publication_state: Literal["SUCCESS", "TERMINAL"]
    terminal_code: ContestProfileTerminalCode | None
    replay_content_sha256: Sha256
    replay_sha256: Sha256

    @model_validator(mode="after")
    def validate_replay(self) -> Self:
        if (self.publication_state == "SUCCESS") != (self.terminal_code is None):
            raise ValueError("replay state and terminal code are inconsistent")
        expected_content = canonical_sha256(
            self.model_dump(
                exclude={"replay_ordinal", "replay_content_sha256", "replay_sha256"},
                mode="json",
            )
        )
        if self.replay_content_sha256 != expected_content:
            raise ValueError("replay content digest drifted")
        if self.replay_sha256 != self.replay_content_sha256:
            raise ValueError("replay attestation digest drifted")
        return self


class ContestPlan54Handoff(StrictContract):
    schema_version: Literal["itda.catalog-contest-use-plan54-handoff.v1"] = (
        "itda.catalog-contest-use-plan54-handoff.v1"
    )
    scope: ContestUseScope = ContestUseScope.NONCOMMERCIAL_CONTEST_DEMO_EVALUATION
    commercial_production_rights_review_required: Literal[True] = True
    execution_mode: Literal["captured_replay"] = "captured_replay"
    authority_required: Literal[False] = False
    credential_required: Literal[False] = False
    provider_traffic_allowed: Literal[False] = False
    provider_attempt_inventory: tuple[()] = ()
    mode_security_roots: dict[str, str]
    mode_security_roots_sha256: Sha256
    contest_policy_sha256: Sha256
    contest_rights_root_sha256: Sha256
    official_dataset_grants_root_sha256: Sha256
    asset_exclusions_root_sha256: Sha256
    complete_universe_root_sha256: Sha256
    pre_handoff_content_sha256: Sha256
    first_replay_sha256: Sha256
    second_replay_sha256: Sha256
    eligible_pool_sha256: Sha256
    exact_36_sha256: Sha256
    quota_proof_sha256: Sha256
    missingness_state_root_sha256: Sha256
    warning_state_root_sha256: Sha256
    confidence_state_root_sha256: Sha256
    commercial_review_requirement_sha256: Sha256
    immutable_parents_root_sha256: Sha256
    eligible_candidate_count: Literal[40]
    eligible_group_counts: dict[RepresentationGroup, int]
    capped_capacity: Literal[38]
    final_quotas: dict[RepresentationGroup, int]
    selectable_candidate_count: Literal[36]
    preview_is_canonical_catalog: Literal[False] = False
    human_choice_and_order_required: Literal[True] = True
    plan54_reachable: Literal[True] = True
    handoff_sha256: Sha256

    @model_validator(mode="after")
    def validate_handoff(self) -> Self:
        expected_keys = {
            "execution_mode",
            "network_denial_policy_sha256",
            "null_authority_state_sha256",
            "null_credential_state_sha256",
            "provider_attempt_inventory_sha256",
        }
        if set(self.mode_security_roots) != expected_keys:
            raise ValueError("captured replay mode-security roots drifted")
        if self.mode_security_roots_sha256 != _canonical_line_sha256(self.mode_security_roots):
            raise ValueError("captured replay mode-security digest drifted")
        expected = canonical_sha256(self.model_dump(exclude={"handoff_sha256"}, mode="json"))
        if self.handoff_sha256 != expected:
            raise ValueError("Plan 54 contest handoff digest drifted")
        return self


class ContestTerminalReason(StrictContract):
    reason_code: Annotated[str, Field(strict=True, pattern=r"^[A-Z][A-Z0-9_]*$")]
    source_neutral_id: Annotated[
        str | None,
        Field(strict=True, pattern=r"^place:[0-9a-f]{64}$"),
    ] = None
    predicate_root_sha256: Sha256 | None = None
    evidence_root_sha256: Sha256 | None = None


class ContestProfileTerminal(StrictContract):
    schema_version: Literal["itda.catalog-contest-use-terminal.v1"] = (
        "itda.catalog-contest-use-terminal.v1"
    )
    publication_state: Literal["TERMINAL"] = "TERMINAL"
    terminal_code: ContestProfileTerminalCode
    exit_code: Literal[27] = 27
    predicate_version: Literal["contest-profile-terminal-precedence-v1"] = (
        "contest-profile-terminal-precedence-v1"
    )
    scope: ContestUseScope = ContestUseScope.NONCOMMERCIAL_CONTEST_DEMO_EVALUATION
    commercial_production_rights_review_required: Literal[True] = True
    ordered_immutable_parents: tuple[dict[str, Any], ...]
    reasons: Annotated[tuple[ContestTerminalReason, ...], Field(min_length=1)]
    available_replay_roots: tuple[Sha256, ...]
    mode_security_roots: dict[str, str]
    mode_security_roots_sha256: Sha256
    plan54_reachable: Literal[False] = False
    handoff_created: Literal[False] = False
    summary_created: Literal[False] = False
    review_created: Literal[False] = False
    provider_traffic_observed: Literal[False] = False
    credential_accessed: Literal[False] = False
    authority_accessed: Literal[False] = False
    split_created: Literal[False] = False
    schema_mutated: Literal[False] = False
    catalog_activated: Literal[False] = False
    seal_created: Literal[False] = False
    terminal_payload_sha256: Sha256

    @model_validator(mode="after")
    def validate_terminal(self) -> Self:
        reason_payloads = [reason.model_dump(mode="json") for reason in self.reasons]
        if reason_payloads != sorted(
            reason_payloads,
            key=lambda item: canonical_sha256(item).encode("ascii"),
        ):
            raise ValueError("terminal reasons must use canonical digest order")
        if self.mode_security_roots_sha256 != _canonical_line_sha256(self.mode_security_roots):
            raise ValueError("terminal mode-security digest drifted")
        expected = canonical_sha256(
            self.model_dump(exclude={"terminal_payload_sha256"}, mode="json")
        )
        if self.terminal_payload_sha256 != expected:
            raise ValueError("contest terminal payload digest drifted")
        return self


class ContestGenerationChild(StrictContract):
    relpath: Annotated[str, Field(strict=True, pattern=r"^[a-z0-9][a-z0-9-]*\.json$")]
    entry_type: Literal["regular_file"] = "regular_file"
    mode: Literal["0600"] = "0600"
    size_bytes: Annotated[int, Field(strict=True, ge=2, le=100_000_000)]
    file_sha256: Sha256


class ContestGenerationManifest(StrictContract):
    schema_version: Literal["itda.catalog-contest-use-generation-manifest.v1"] = (
        "itda.catalog-contest-use-generation-manifest.v1"
    )
    publication_state: Literal["SUCCESS", "TERMINAL"]
    ordered_parents: tuple[dict[str, Any], ...]
    payload_inventory: tuple[ContestGenerationChild, ...]
    generation_sha256: Sha256

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        names = tuple(child.relpath for child in self.payload_inventory)
        expected_names = (
            (
                "candidate-accounting.json",
                "first-replay.json",
                "plan54-handoff.json",
                "policy.json",
                "second-replay.json",
                "selection-frontier.json",
                "source-grants.json",
            )
            if self.publication_state == "SUCCESS"
            else ("terminal.json",)
        )
        if names != expected_names:
            raise ValueError("generation payload inventory changed its closed branch order")
        if "generation-manifest.json" in names:
            raise ValueError("generation manifest cannot inventory itself")
        expected = canonical_sha256(self.model_dump(exclude={"generation_sha256"}, mode="json"))
        if self.generation_sha256 != expected:
            raise ValueError("generation descriptor digest drifted")
        return self


__all__ = [
    "ACCOUNTING_SCHEMA_VERSION",
    "AxisEvidenceBasis",
    "CONTEST_SCOPE",
    "ContestCandidateAccounting",
    "ContestGenerationChild",
    "ContestGenerationManifest",
    "ContestPlan54Handoff",
    "ContestProfileConfidence",
    "ContestProfileTerminal",
    "ContestProfileTerminalCode",
    "ContestReplayAttestation",
    "ContestSelectionFrontier",
    "ContestTerminalReason",
    "ContestUsePolicy",
    "ContestUseScope",
    "DatasetPermissionDisposition",
    "EvidenceAvailability",
]
