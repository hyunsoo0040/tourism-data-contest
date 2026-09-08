"""Real 36-place split and membership-free approval contracts."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from datetime import datetime
from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from itda.contracts.base import Sha256, StrictContract, require_utc
from itda.domain.canonical import canonical_sha256


class RealManifestMember(StrictContract):
    """One restricted real catalog member and its hard component."""

    canonical_place_id: Annotated[
        str,
        Field(strict=True, pattern=r"^place:[A-Za-z0-9._:-]{1,153}$"),
    ]
    split: Literal["DEV", "BLIND"]
    component_id: Annotated[
        str,
        Field(strict=True, pattern=r"^component:[A-Za-z0-9._:-]{1,149}$"),
    ]


class RealSplitManifest(StrictContract):
    """Restricted exact 36/24/12 membership bound to approved catalog truth."""

    schema_version: Literal["real-split-manifest-v1"] = "real-split-manifest-v1"
    manifest_version: Annotated[str, Field(strict=True, min_length=1, max_length=128)]
    canonicalization_version: Literal["canonical-json-v1"] = "canonical-json-v1"
    catalog_manifest_sha256: Sha256
    catalog_approval_sha256: Sha256
    catalog_adjudication_sha256: Sha256
    relationship_revision_sha256: Sha256
    algorithm_version: Annotated[str, Field(strict=True, min_length=1, max_length=128)]
    seed: Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)]
    component_inputs_sha256: Sha256
    balance_inputs_sha256: Sha256
    objective_score: Annotated[
        str,
        Field(strict=True, pattern=r"^-?[0-9]+\.[0-9]{6}$"),
    ]
    members: tuple[RealManifestMember, ...]
    membership_sha256: Sha256 | None = None

    def canonical_members(self) -> tuple[RealManifestMember, ...]:
        return tuple(sorted(self.members, key=lambda item: item.canonical_place_id))

    def canonical_payload(self) -> dict[str, object]:
        return {
            **self.model_dump(exclude={"members"}, mode="json"),
            "members": [member.model_dump(mode="json") for member in self.canonical_members()],
        }

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        if len(self.members) != 36:
            raise ValueError("real manifest requires exactly 24 DEV and 12 BLIND members")
        if (
            sum(member.split == "DEV" for member in self.members) != 24
            or sum(member.split == "BLIND" for member in self.members) != 12
        ):
            raise ValueError("real manifest requires exactly 24 DEV and 12 BLIND members")
        identifiers = tuple(member.canonical_place_id for member in self.members)
        if len(set(identifiers)) != 36:
            raise ValueError("canonical_place_id values must be unique")
        validate_component_closure(self)
        expected = canonical_sha256(
            [member.model_dump(mode="json") for member in self.canonical_members()]
        )
        if self.membership_sha256 is None:
            object.__setattr__(self, "membership_sha256", expected)
        elif self.membership_sha256 != expected:
            raise ValueError("membership_sha256 does not match canonical membership")
        return self


class SplitApprovalRequest(StrictContract):
    """Membership-free public request for the separate split approval."""

    schema_version: Literal["split-approval-request-v1"] = "split-approval-request-v1"
    manifest_version: Annotated[str, Field(strict=True, min_length=1, max_length=128)]
    catalog_manifest_sha256: Sha256
    catalog_approval_sha256: Sha256
    catalog_adjudication_sha256: Sha256
    relationship_revision_sha256: Sha256
    split_manifest_sha256: Sha256
    membership_sha256: Sha256
    algorithm_version: Annotated[str, Field(strict=True, min_length=1, max_length=128)]
    seed: Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)]
    component_inputs_sha256: Sha256
    balance_inputs_sha256: Sha256
    dev_count: Literal[24] = 24
    blind_count: Literal[12] = 12
    component_closure_valid: Literal[True] = True
    exact_counts_valid: Literal[True] = True
    split_approval_request_sha256: Sha256 | None = None

    def canonical_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json")

    @model_validator(mode="after")
    def validate_request_hash(self) -> Self:
        expected = canonical_sha256(
            self.model_dump(exclude={"split_approval_request_sha256"}, mode="json")
        )
        if self.split_approval_request_sha256 is None:
            object.__setattr__(self, "split_approval_request_sha256", expected)
        elif self.split_approval_request_sha256 != expected:
            raise ValueError("split approval request sha256 does not match canonical fields")
        return self


class SplitApproval(StrictContract):
    """Separate human approval that copies no restricted membership."""

    schema_version: Literal["split-approval-v1"] = "split-approval-v1"
    catalog_manifest_sha256: Sha256
    catalog_approval_sha256: Sha256
    split_manifest_sha256: Sha256
    confirm_sha256: Sha256
    reviewer_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    approved_at: datetime
    split_approval_request_sha256: Sha256 | None = None
    split_approval_sha256: Sha256 | None = None

    @field_validator("approved_at")
    @classmethod
    def approved_at_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="approved_at")

    @model_validator(mode="after")
    def validate_approval(self) -> Self:
        if self.confirm_sha256 != self.split_manifest_sha256:
            raise ValueError("split manifest sha256 confirmation must match full digest")
        expected = canonical_sha256(self.model_dump(exclude={"split_approval_sha256"}, mode="json"))
        if self.split_approval_sha256 is None:
            object.__setattr__(self, "split_approval_sha256", expected)
        elif self.split_approval_sha256 != expected:
            raise ValueError("split approval sha256 does not match canonical fields")
        return self


def validate_component_closure(manifest: RealSplitManifest) -> None:
    """Reject every hard component that crosses DEV/BLIND."""

    component_splits: defaultdict[str, set[str]] = defaultdict(set)
    for member in manifest.members:
        component_splits[member.component_id].add(member.split)
    if any(len(splits) != 1 for splits in component_splits.values()):
        raise ValueError("hard component cannot be split across DEV and BLIND")


def validate_balance_inputs(payload: Mapping[str, object]) -> None:
    """Reject downstream labels, model outputs, or BLIND results from split inputs."""

    forbidden_fragments = (
        "label",
        "score",
        "prompt",
        "model",
        "embedding",
        "blind_result",
        "prediction",
        "ndcg",
    )
    stack: list[object] = [payload]
    while stack:
        value = stack.pop()
        if isinstance(value, Mapping):
            for key, child in value.items():
                rendered = str(key).casefold()
                if any(fragment in rendered for fragment in forbidden_fragments):
                    raise ValueError("balance inputs contain forbidden later-stage information")
                stack.append(child)
        elif isinstance(value, (list, tuple)):
            stack.extend(value)


class AuditedProviderFieldPresence(StrictContract):
    """Frozen provider-field presence used only for REINF-13 completeness."""

    official_description: bool
    odii_script: bool
    official_metadata: bool
    qualified_image: bool
    operating_information: bool

    @property
    def ordinal(self) -> int:
        return sum(
            (
                self.official_description,
                self.odii_script,
                self.official_metadata,
                self.qualified_image,
                self.operating_information,
            )
        )


class RealSplitBalanceRow(StrictContract):
    """One human-authoritative, source-neutral REINF-13 input row."""

    source_neutral_place_id: Annotated[str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")]
    history_tradition: bool
    emotion_image: bool
    rest_immersion: bool
    audited_provider_fields: AuditedProviderFieldPresence
    evidence_digest: Sha256 | None = None

    @model_validator(mode="before")
    @classmethod
    def reject_unsafe_fields(cls, value: object) -> object:
        if isinstance(value, Mapping):
            allowed = {
                "source_neutral_place_id",
                "history_tradition",
                "emotion_image",
                "rest_immersion",
                "audited_provider_fields",
                "evidence_digest",
            }
            if set(value) - allowed:
                raise ValueError("balance row contains forbidden non-safe fields")
            validate_balance_inputs(value)
        return value


class RealSplitComponent(StrictContract):
    """One canonical hard component whose members cannot be separated."""

    component_id: Annotated[str, Field(strict=True, pattern=r"^component:[A-Za-z0-9._:-]+$")]
    members: tuple[Annotated[str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")], ...]

    @model_validator(mode="after")
    def validate_component(self) -> Self:
        canonical = tuple(sorted(self.members, key=lambda item: item.encode("utf-8")))
        if not canonical or len(set(canonical)) != len(canonical) or canonical != self.members:
            raise ValueError("hard component members must be unique canonical source-neutral IDs")
        return self


class AuthoritativeHardComponentSet(StrictContract):
    schema_version: Literal["itda.real-split-hard-components.v1"] = (
        "itda.real-split-hard-components.v1"
    )
    active_revision_sha256: Sha256
    authoritative_relationship_leaves_sha256: Sha256
    components: tuple[RealSplitComponent, ...]
    component_universe_sha256: Sha256


class RealSplitReachabilityCertificate(StrictContract):
    blind_size: Annotated[int, Field(strict=True, ge=0)]
    reachable_sizes: tuple[int, ...]
    exact_size_reachable: bool
    exact_assignment_count: Annotated[int, Field(strict=True, ge=0)]
    tolerance_feasible_assignment_count: Annotated[int, Field(strict=True, ge=0)]
    dp_layer_sha256s: tuple[Sha256, ...]
    terminal_state_count: Annotated[int, Field(strict=True, ge=0)]
    certificate_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_reachability(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"certificate_sha256"}, mode="json"))
        if self.certificate_sha256 is None:
            object.__setattr__(self, "certificate_sha256", expected)
        elif self.certificate_sha256 != expected:
            raise ValueError("reachability certificate hash is stale")
        return self


class RealSplitOptimalityProof(StrictContract):
    schema_version: Literal["itda.real-split-optimality-proof.v2"] = (
        "itda.real-split-optimality-proof.v2"
    )
    algorithm_version: Literal["reinforcement-13-exact-dp-v2"] = "reinforcement-13-exact-dp-v2"
    seed: Literal[42] = 42
    priority_rule_version: Literal["seeded-component-additive-priority-v1"] = (
        "seeded-component-additive-priority-v1"
    )
    objective_order: tuple[
        Literal["max_axis_deviation_numerator"],
        Literal["total_axis_deviation_numerator"],
        Literal["max_completeness_bin_deviation_numerator"],
        Literal["total_completeness_bin_deviation_numerator"],
        Literal["seed_42_component_priority_sum"],
    ]
    tolerance: Literal[1] = 1
    tolerance_numerator: Literal[3] = 3
    completeness_rule_version: Literal["audited-provider-presence-count-v1"] = (
        "audited-provider-presence-count-v1"
    )
    completeness_field_order: tuple[str, ...]
    completeness_bin_order: tuple[int, ...]
    completeness_rule_sha256: Sha256
    safe_input_rows: tuple[RealSplitBalanceRow, ...]
    safe_input_sha256: Sha256
    components: tuple[RealSplitComponent, ...]
    component_universe_sha256: Sha256
    component_priority_rows: tuple[dict[str, object], ...]
    component_priority_root_sha256: Sha256
    authority_bindings_sha256: Sha256 | None = None
    exact_targets: dict[str, str]
    exact_targets_sha256: Sha256
    reachability: RealSplitReachabilityCertificate
    objective_tuple: tuple[int, int, int, int, int] | None
    unconstrained_objective_tuple: tuple[int, int, int, int, int] | None
    deviation_numerators: dict[str, int]
    winning_membership_sha256: Sha256 | None
    proof_certificate_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_proof(self) -> Self:
        expected = canonical_sha256(
            self.model_dump(exclude={"proof_certificate_sha256"}, mode="json")
        )
        if self.proof_certificate_sha256 is None:
            object.__setattr__(self, "proof_certificate_sha256", expected)
        elif self.proof_certificate_sha256 != expected:
            raise ValueError("optimality proof certificate hash is stale")
        return self


class RealSplitCandidate(StrictContract):
    schema_version: Literal["itda.real-split-candidate.v2"] = "itda.real-split-candidate.v2"
    dev_members: tuple[Annotated[str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")], ...]
    blind_members: tuple[Annotated[str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")], ...]
    membership_sha256: Sha256
    safe_input_sha256: Sha256
    component_universe_sha256: Sha256
    proof_certificate_sha256: Sha256
    authority_bindings_sha256: Sha256 | None = None
    candidate_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_candidate(self) -> Self:
        if len(self.dev_members) + len(self.blind_members) != 36:
            raise ValueError("real split candidate must contain exact active 36")
        if len(self.dev_members) != 24 or len(self.blind_members) != 12:
            raise ValueError("real split candidate requires exact 24/12 membership")
        members = self.dev_members + self.blind_members
        if len(set(members)) != 36:
            raise ValueError("real split candidate membership must be unique")
        expected = canonical_sha256(self.model_dump(exclude={"candidate_sha256"}, mode="json"))
        if self.candidate_sha256 is None:
            object.__setattr__(self, "candidate_sha256", expected)
        elif self.candidate_sha256 != expected:
            raise ValueError("real split candidate hash is stale")
        return self


class RealSplitBalanceOutcome(StrictContract):
    schema_version: Literal["itda.real-split-balance-outcome.v2"] = (
        "itda.real-split-balance-outcome.v2"
    )
    status: Literal["FEASIBLE", "BALANCE_INFEASIBLE"]
    proof: RealSplitOptimalityProof
    candidate: RealSplitCandidate | None
    outcome_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        if (self.status == "FEASIBLE") != (self.candidate is not None):
            raise ValueError("only a feasible proof may carry a split candidate")
        expected = canonical_sha256(self.model_dump(exclude={"outcome_sha256"}, mode="json"))
        if self.outcome_sha256 is None:
            object.__setattr__(self, "outcome_sha256", expected)
        elif self.outcome_sha256 != expected:
            raise ValueError("balance outcome hash is stale")
        return self


class SafeInputCandidateReviewRow(StrictContract):
    source_neutral_place_id: Annotated[str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")]
    history_tradition: None = None
    emotion_image: None = None
    rest_immersion: None = None
    audited_provider_fields: AuditedProviderFieldPresence
    completeness_ordinal: Annotated[int, Field(strict=True, ge=0, le=5)]
    evidence_refs: tuple[str, ...]
    evidence_digest: Sha256
    missing_evidence: tuple[str, ...]
    review_status: Literal["PENDING_HUMAN_AXIS_REVIEW"] = "PENDING_HUMAN_AXIS_REVIEW"
    row_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_review_row(self) -> Self:
        if self.completeness_ordinal != self.audited_provider_fields.ordinal:
            raise ValueError("completeness ordinal does not match audited field presence")
        expected = canonical_sha256(self.model_dump(exclude={"row_sha256"}, mode="json"))
        if self.row_sha256 is None:
            object.__setattr__(self, "row_sha256", expected)
        elif self.row_sha256 != expected:
            raise ValueError("safe-input candidate row hash is stale")
        return self


class SafeInputCandidateReviewPackage(StrictContract):
    schema_version: Literal["itda.real-split-safe-input-candidate-review.v1"] = (
        "itda.real-split-safe-input-candidate-review.v1"
    )
    status: Literal["HUMAN_REVIEW_REQUIRED"] = "HUMAN_REVIEW_REQUIRED"
    authoritative: Literal[False] = False
    split_publication_blocked: Literal[True] = True
    catalog_revision_sha256: Sha256
    catalog_activation_event_sha256: Sha256
    catalog_approval_sha256: Sha256
    authoritative_relationship_leaves_sha256: Sha256
    active_ordered_place_ids_sha256: Sha256
    ordered_source_neutral_place_ids_sha256: Sha256
    axis_rule_candidate: dict[str, object]
    axis_rule_candidate_sha256: Sha256
    completeness_rule_version: Literal["audited-provider-presence-count-v1"] = (
        "audited-provider-presence-count-v1"
    )
    completeness_field_order: tuple[str, ...]
    completeness_bin_order: tuple[int, ...]
    completeness_rule_sha256: Sha256
    rows: tuple[SafeInputCandidateReviewRow, ...]
    rows_root_sha256: Sha256
    review_package_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_package(self) -> Self:
        if self.axis_rule_candidate_sha256 != canonical_sha256(self.axis_rule_candidate):
            raise ValueError("axis-rule candidate hash is stale")
        ids = tuple(row.source_neutral_place_id for row in self.rows)
        if len(ids) != 36 or len(set(ids)) != 36:
            raise ValueError("safe-input review requires exact active 36")
        if ids != tuple(sorted(ids, key=lambda item: item.encode("utf-8"))):
            raise ValueError("safe-input review rows must use canonical ID order")
        expected = canonical_sha256(self.model_dump(exclude={"review_package_sha256"}, mode="json"))
        if self.review_package_sha256 is None:
            object.__setattr__(self, "review_package_sha256", expected)
        elif self.review_package_sha256 != expected:
            raise ValueError("safe-input review package hash is stale")
        return self


class HumanAxisDecision(StrictContract):
    """One human-authoritative axis decision preserving the reviewed draft reason."""

    draft_value: Literal["TRUE", "FALSE", "UNRESOLVED"]
    authoritative_value: bool
    original_reason: Annotated[str, Field(strict=True, min_length=1)]
    decision_basis: Literal[
        "HUMAN_CONFIRMED_DRAFT",
        "HUMAN_DESCRIPTION_REVIEW_NO_EXPLICIT_SUPPORT",
    ]


class HumanAxisJudgmentApprovalRow(StrictContract):
    source_neutral_place_id: Annotated[str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")]
    description_sha256: Sha256
    source_evidence_digest: Sha256
    source_evidence_refs: tuple[str, ...]
    history_tradition: HumanAxisDecision
    emotion_image: HumanAxisDecision
    rest_immersion: HumanAxisDecision
    row_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_row(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"row_sha256"}, mode="json"))
        if self.row_sha256 is None:
            object.__setattr__(self, "row_sha256", expected)
        elif self.row_sha256 != expected:
            raise ValueError("human axis approval row hash is stale")
        return self


class HumanAxisRuleRoot(StrictContract):
    schema_version: Literal["itda.real-split-human-axis-rule.v1"] = (
        "itda.real-split-human-axis-rule.v1"
    )
    status: Literal["HUMAN_AUTHORITATIVE"] = "HUMAN_AUTHORITATIVE"
    source_draft_semantic_sha256: Sha256
    source_review_package_sha256: Sha256
    axis_rule_candidate_sha256: Sha256
    catalog_revision_sha256: Sha256
    catalog_activation_event_sha256: Sha256
    catalog_approval_sha256: Sha256
    authoritative_relationship_leaves_sha256: Sha256
    active_ordered_place_ids_sha256: Sha256
    human_resolution_rule: Annotated[str, Field(strict=True, min_length=1)]
    non_inference_guard: Annotated[str, Field(strict=True, min_length=1)]
    review_scope: Literal["COMPLETED_ROW_LEVEL_IMMUTABLE_OFFICIAL_DESCRIPTION_REVIEW"] = (
        "COMPLETED_ROW_LEVEL_IMMUTABLE_OFFICIAL_DESCRIPTION_REVIEW"
    )
    unresolved_before: Literal[17] = 17
    unresolved_after: Literal[0] = 0
    rule_root_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_rule(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"rule_root_sha256"}, mode="json"))
        if self.rule_root_sha256 is None:
            object.__setattr__(self, "rule_root_sha256", expected)
        elif self.rule_root_sha256 != expected:
            raise ValueError("human axis rule root is stale")
        return self


class HumanAxisJudgmentApproval(StrictContract):
    schema_version: Literal["itda.real-split-human-axis-approval.v1"] = (
        "itda.real-split-human-axis-approval.v1"
    )
    status: Literal["HUMAN_APPROVED_AUTHORITATIVE"] = "HUMAN_APPROVED_AUTHORITATIVE"
    authoritative: Literal[True] = True
    source_draft_semantic_sha256: Sha256
    source_review_package_sha256: Sha256
    axis_rule_candidate_sha256: Sha256
    human_axis_rule_root_sha256: Sha256
    catalog_revision_sha256: Sha256
    catalog_activation_event_sha256: Sha256
    catalog_approval_sha256: Sha256
    authoritative_relationship_leaves_sha256: Sha256
    active_ordered_place_ids_sha256: Sha256
    reviewer_id: Annotated[str, Field(strict=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")]
    approved_at: datetime
    human_choice: Literal["1"] = "1"
    unresolved_before: Literal[17] = 17
    unresolved_after: Literal[0] = 0
    rows: tuple[HumanAxisJudgmentApprovalRow, ...]
    rows_root_sha256: Sha256
    approval_sha256: Sha256 | None = None

    @field_validator("approved_at")
    @classmethod
    def approved_at_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="axis approval timestamp")

    @model_validator(mode="after")
    def validate_approval(self) -> Self:
        if len(self.rows) != 36 or len({row.source_neutral_place_id for row in self.rows}) != 36:
            raise ValueError("human axis approval requires exact active 36")
        if self.rows_root_sha256 != canonical_sha256(
            [row.model_dump(mode="json") for row in self.rows]
        ):
            raise ValueError("human axis approval row root is stale")
        if any(
            decision.draft_value == "UNRESOLVED" and decision.authoritative_value
            for row in self.rows
            for decision in (row.history_tradition, row.emotion_image, row.rest_immersion)
        ):
            raise ValueError("the selected human rule resolves every draft UNRESOLVED to false")
        expected = canonical_sha256(self.model_dump(exclude={"approval_sha256"}, mode="json"))
        if self.approval_sha256 is None:
            object.__setattr__(self, "approval_sha256", expected)
        elif self.approval_sha256 != expected:
            raise ValueError("human axis approval hash is stale")
        return self


class AuthoritativeSafeInputRoot(StrictContract):
    schema_version: Literal["itda.real-split-authoritative-safe-input.v1"] = (
        "itda.real-split-authoritative-safe-input.v1"
    )
    status: Literal["HUMAN_AUTHORITATIVE"] = "HUMAN_AUTHORITATIVE"
    unresolved_count: Literal[0] = 0
    source_draft_semantic_sha256: Sha256
    source_review_package_sha256: Sha256
    human_axis_rule_root_sha256: Sha256
    human_axis_approval_sha256: Sha256
    catalog_revision_sha256: Sha256
    catalog_activation_event_sha256: Sha256
    catalog_approval_sha256: Sha256
    authoritative_relationship_leaves_sha256: Sha256
    active_ordered_place_ids_sha256: Sha256
    rows: tuple[RealSplitBalanceRow, ...]
    safe_input_sha256: Sha256
    authoritative_safe_input_root_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_root(self) -> Self:
        ids = tuple(row.source_neutral_place_id for row in self.rows)
        if (
            len(ids) != 36
            or len(set(ids)) != 36
            or ids != tuple(sorted(ids, key=lambda item: item.encode("utf-8")))
        ):
            raise ValueError("authoritative safe input requires canonical exact active 36")
        if self.safe_input_sha256 != canonical_sha256(
            [row.model_dump(mode="json") for row in self.rows]
        ):
            raise ValueError("authoritative safe input row root is stale")
        expected = canonical_sha256(
            self.model_dump(exclude={"authoritative_safe_input_root_sha256"}, mode="json")
        )
        if self.authoritative_safe_input_root_sha256 is None:
            object.__setattr__(self, "authoritative_safe_input_root_sha256", expected)
        elif self.authoritative_safe_input_root_sha256 != expected:
            raise ValueError("authoritative safe input root is stale")
        return self


class RealSplitCandidateState(StrictContract):
    schema_version: Literal["itda.real-split-candidate-state.v2"] = (
        "itda.real-split-candidate-state.v2"
    )
    status: Literal["CANDIDATE_ONLY"] = "CANDIDATE_ONLY"
    outcome_sha256: Sha256
    candidate_sha256: Sha256
    active_bindings_sha256: Sha256
    authority_bindings_sha256: Sha256
    authoritative_manifest_sha256: None = None
    split_approval_sha256: None = None
    seal_sha256: None = None
    state_attestation_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        expected = canonical_sha256(
            self.model_dump(exclude={"state_attestation_sha256"}, mode="json")
        )
        if self.state_attestation_sha256 is None:
            object.__setattr__(self, "state_attestation_sha256", expected)
        elif self.state_attestation_sha256 != expected:
            raise ValueError("candidate state hash is stale")
        return self


class RealSplitMaterializationRequest(StrictContract):
    schema_version: Literal["itda.real-split-materialization-request.v2"] = (
        "itda.real-split-materialization-request.v2"
    )
    action: Literal["real-split-materialize"] = "real-split-materialize"
    request_sha256: Sha256 | None = None
    state_attestation_sha256: Sha256
    target_sha256: Sha256
    reviewer_id: Annotated[str, Field(strict=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")]
    binding_sha256: Sha256
    nonce: Sha256
    issued_at: datetime
    expires_at: datetime
    outcome_sha256: Sha256
    proof_certificate_sha256: Sha256
    candidate_sha256: Sha256
    split_semantic_sha256: Sha256
    active_bindings_sha256: Sha256
    authority_bindings_sha256: Sha256
    dev_count: Literal[24] = 24
    blind_count: Literal[12] = 12

    @field_validator("issued_at", "expires_at")
    @classmethod
    def timestamps_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="materialization authority timestamp")

    @model_validator(mode="after")
    def validate_request(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("materialization request expiry must follow issuance")
        expected = canonical_sha256(self.model_dump(exclude={"request_sha256"}, mode="json"))
        if self.request_sha256 is None:
            object.__setattr__(self, "request_sha256", expected)
        elif self.request_sha256 != expected:
            raise ValueError("materialization request hash is stale")
        return self

    def expected_token(self):
        from itda.contracts.authority import AuthorityTokenV2

        return AuthorityTokenV2(
            action=self.action,
            request_sha256=self.request_sha256,
            state_attestation_sha256=self.state_attestation_sha256,
            target_sha256=self.target_sha256,
            reviewer_id=self.reviewer_id,
            binding_sha256=self.binding_sha256,
            nonce=self.nonce,
        )


class MaterializedRealSplitManifest(StrictContract):
    schema_version: Literal["itda.materialized-real-split-manifest.v2"] = (
        "itda.materialized-real-split-manifest.v2"
    )
    status: Literal["MATERIALIZED_UNAPPROVED"] = "MATERIALIZED_UNAPPROVED"
    dev_members: tuple[str, ...]
    blind_members: tuple[str, ...]
    membership_sha256: Sha256
    outcome_sha256: Sha256
    proof_certificate_sha256: Sha256
    candidate_sha256: Sha256
    split_approval_sha256: None = None
    seal_sha256: None = None
    manifest_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_materialized(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"manifest_sha256"}, mode="json"))
        if self.manifest_sha256 is None:
            object.__setattr__(self, "manifest_sha256", expected)
        elif self.manifest_sha256 != expected:
            raise ValueError("materialized manifest hash is stale")
        return self


class RealSplitDeterminismReport(StrictContract):
    schema_version: Literal["itda.real-split-determinism-report.v2"] = (
        "itda.real-split-determinism-report.v2"
    )
    algorithm_version: str
    seed: Literal[42] = 42
    safe_input_sha256: Sha256
    component_universe_sha256: Sha256
    proof_certificate_sha256: Sha256
    outcome_sha256: Sha256
    membership_sha256: Sha256
    report_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"report_sha256"}, mode="json"))
        if self.report_sha256 is None:
            object.__setattr__(self, "report_sha256", expected)
        elif self.report_sha256 != expected:
            raise ValueError("determinism report hash is stale")
        return self


class RealSplitMaterializationBundle(StrictContract):
    schema_version: Literal["itda.real-split-materialization-bundle.v2"] = (
        "itda.real-split-materialization-bundle.v2"
    )
    request_sha256: Sha256
    state_attestation_sha256: Sha256
    target_sha256: Sha256
    manifest_sha256: Sha256
    report_sha256: Sha256
    result_sha256: Sha256
    bundle_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_bundle(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"bundle_sha256"}, mode="json"))
        if self.bundle_sha256 is None:
            object.__setattr__(self, "bundle_sha256", expected)
        elif self.bundle_sha256 != expected:
            raise ValueError("materialization bundle hash is stale")
        return self


def build_split_approval_request(manifest: RealSplitManifest) -> SplitApprovalRequest:
    """Serialize only counts, validations, versions, and full hashes."""

    validate_component_closure(manifest)
    if manifest.membership_sha256 is None:
        raise ValueError("real manifest requires a canonical membership sha256")
    return SplitApprovalRequest(
        manifest_version=manifest.manifest_version,
        catalog_manifest_sha256=manifest.catalog_manifest_sha256,
        catalog_approval_sha256=manifest.catalog_approval_sha256,
        catalog_adjudication_sha256=manifest.catalog_adjudication_sha256,
        relationship_revision_sha256=manifest.relationship_revision_sha256,
        split_manifest_sha256=canonical_sha256(manifest.canonical_payload()),
        membership_sha256=manifest.membership_sha256,
        algorithm_version=manifest.algorithm_version,
        seed=manifest.seed,
        component_inputs_sha256=manifest.component_inputs_sha256,
        balance_inputs_sha256=manifest.balance_inputs_sha256,
    )


def verify_split_approval_request(
    request: SplitApprovalRequest,
    manifest: RealSplitManifest,
) -> None:
    """Re-derive every public request field from restricted membership."""

    expected = build_split_approval_request(manifest)
    if request != expected:
        raise ValueError("split approval request has a stale catalog approval or parent")


def synthetic_membership_free_request() -> SplitApprovalRequest:
    """Return a safe boundary probe without constructing any membership."""

    return SplitApprovalRequest(
        manifest_version="boundary-probe-v1",
        catalog_manifest_sha256="1" * 64,
        catalog_approval_sha256="2" * 64,
        catalog_adjudication_sha256="3" * 64,
        relationship_revision_sha256="4" * 64,
        split_manifest_sha256="5" * 64,
        membership_sha256="6" * 64,
        algorithm_version="boundary-probe-v1",
        seed=0,
        component_inputs_sha256="7" * 64,
        balance_inputs_sha256="8" * 64,
    )


__all__ = [
    "AuditedProviderFieldPresence",
    "AuthoritativeSafeInputRoot",
    "AuthoritativeHardComponentSet",
    "HumanAxisDecision",
    "HumanAxisJudgmentApproval",
    "HumanAxisJudgmentApprovalRow",
    "HumanAxisRuleRoot",
    "MaterializedRealSplitManifest",
    "RealManifestMember",
    "RealSplitBalanceOutcome",
    "RealSplitBalanceRow",
    "RealSplitCandidate",
    "RealSplitCandidateState",
    "RealSplitComponent",
    "RealSplitDeterminismReport",
    "RealSplitManifest",
    "RealSplitMaterializationBundle",
    "RealSplitMaterializationRequest",
    "RealSplitOptimalityProof",
    "RealSplitReachabilityCertificate",
    "SafeInputCandidateReviewPackage",
    "SafeInputCandidateReviewRow",
    "SplitApproval",
    "SplitApprovalRequest",
    "build_split_approval_request",
    "synthetic_membership_free_request",
    "validate_balance_inputs",
    "validate_component_closure",
    "verify_split_approval_request",
]
